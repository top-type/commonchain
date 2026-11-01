#!/usr/bin/env python3
"""commonchain node. Python 3.12, standard library only.

The background process stores the chain, enforces the Exact rules, relays blocks and messages,
serves Stratum and hands out work. It never calls a model. It follows the heaviest valid chain, and
blocks that code doesn't fully understand are flagged for the agent or the person to read, who can
undo their changes in a later block.
"""
import argparse
import ctypes
import hashlib
import ipaddress
import itertools
import json
import os
import re
import select
import secrets
import socketserver
import struct
import subprocess
import sys
import threading
import time
import http.server
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict

sys.setrecursionlimit(5000)

TEST = os.environ.get('COMMONCHAIN_TEST') == '1'  # fast local test settings, never for the real chain
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SPEC = os.environ.get('COMMONCHAIN_SPEC', os.path.join(HERE, 'README.md'))
MAX_BLOCK = 64 * 1024
BLOCK1_BITS = 0x207fffff if TEST else 0x1e00ffff
BLOCK_TIME = 20 if TEST else 600
HALF_LIFE = 120 if TEST else 3600
GENESIS_TIME = int(os.environ.get('COMMONCHAIN_GENESIS_TIME', 0)) if TEST else 1793539988
REWARD = 10000
HEADER_VERSION = 0x20000000
DIFF1 = 0xffff << (8 * (0x1d - 3))
EN1_SIZE = 4
EN2_SIZE = 4
JOB_REFRESH = 5.0 if TEST else 15.0
MAX_ITEM = 8192
MAX_POOL = 2000
FUTURE_GRACE = 60 if TEST else 600
BEHIND_BLOCKS = 8
MAX_PEERS = 16
UNDO_WINDOW = 8 if TEST else 1008
REWARD_LOCK = 1
NATIVE_MINER = os.path.join(HERE, 'native_miner.exe' if os.name == 'nt' else 'native_miner')
MESSAGE_WAIT = 0 if TEST else 300  # time for the agent or person to drop anything that shouldn't go on chain
MESSAGE_ROOM = 4096
CHAIN_PAGE = 2000


class Invalid(Exception):
    pass


def sha256(b):
    return hashlib.sha256(b).digest()


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def show(b):
    s = ascii(b.decode('utf-8', 'replace'))
    return s if len(s) <= 60 else s[:57] + '...'


LOG_FILE = None


def log(msg):
    line = '%s %s' % (time.strftime('%H:%M:%S'), msg)
    if LOG_FILE:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    else:
        print(line, flush=True)


# --- Ed25519, after the RFC 8032 reference code ---

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
ROOT = pow(2, (P - 1) // 4, P)


def _xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * ROOT) % P
    if (x * x - xx) % P != 0:
        raise ValueError('not on the curve')
    if x % 2 != 0:
        x = P - x
    return x


_BY = 4 * pow(5, P - 2, P) % P
_B = (_xrecover(_BY), _BY)


def _add(a, b):
    x1, y1 = a
    x2, y2 = b
    k = D * x1 * x2 * y1 * y2
    return ((x1 * y2 + x2 * y1) * pow(1 + k, P - 2, P) % P, (y1 * y2 + x1 * x2) * pow(1 - k, P - 2, P) % P)


def _mul(a, e):
    q = (0, 1)
    while e > 0:
        if e & 1:
            q = _add(q, a)
        a = _add(a, a)
        e >>= 1
    return q


def _encode(a):
    x, y = a
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


def _decode(b):
    n = int.from_bytes(b, 'little')
    y = n & ((1 << 255) - 1)
    if y >= P:
        raise ValueError('bad point')
    x = _xrecover(y)
    if (x & 1) != (n >> 255):
        x = P - x
    return (x, y)


def _sha512(m):
    return hashlib.sha512(m).digest()


def _scalar(h):
    return 2**254 + (int.from_bytes(h[:32], 'little') & (2**254 - 8))


def public_key(seed):
    return _encode(_mul(_B, _scalar(_sha512(seed))))


def sign(seed, msg):
    h = _sha512(seed)
    a = _scalar(h)
    pub = _encode(_mul(_B, a))
    r = int.from_bytes(_sha512(h[32:] + msg), 'little') % L
    big_r = _encode(_mul(_B, r))
    k = int.from_bytes(_sha512(big_r + pub + msg), 'little') % L
    return big_r + ((r + k * a) % L).to_bytes(32, 'little')


def verify(pub, msg, sig):
    try:
        if len(pub) != 32 or len(sig) != 64:
            return False
        s = int.from_bytes(sig[32:], 'little')
        if s >= L:
            return False
        big_r = _decode(sig[:32])
        a = _decode(pub)
        k = int.from_bytes(_sha512(sig[:32] + pub + msg), 'little') % L
        return _mul(_B, s) == _add(big_r, _mul(a, k))
    except ValueError:
        return False


# --- targets, bits, work ---


def bits_to_target(bits):
    exp = bits >> 24
    mant = bits & 0x007fffff
    if exp <= 3:
        return mant >> (8 * (3 - exp))
    return mant << (8 * (exp - 3))


def target_to_bits(t):
    size = (t.bit_length() + 7) // 8
    compact = t << (8 * (3 - size)) if size <= 3 else t >> (8 * (size - 3))
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    return compact | (size << 24)


def asert_bits(anchor_height, anchor_parent_time, anchor_bits, height, when, block_time, half_life, max_bits):
    """aserti3-2d as Bitcoin Cash specifies it, with its constants as arguments: the bits of the block after the
    one at this height and time."""
    numerator = (when - anchor_parent_time - block_time * (height - anchor_height + 1)) * 65536
    exponent = numerator // half_life if numerator >= 0 else -(-numerator // half_life)
    shifts = exponent >> 16
    exponent -= shifts * 65536
    factor = ((195766423245049 * exponent + 971821376 * exponent ** 2 + 5127 * exponent ** 3 + 2 ** 47) >> 48) + 65536
    target = bits_to_target(anchor_bits) * factor
    target = (target << shifts if shifts >= 0 else target >> -shifts) >> 16
    if target == 0:
        return target_to_bits(1)
    if target > bits_to_target(max_bits):
        return max_bits
    return target_to_bits(target)


def pick_bits(parent, t):
    """ASERT anchored at genesis. A block more than a half-life after its parent also counts its own time, so a
    chain that loses its miners keeps getting easier instead of getting stuck."""
    return asert_bits(0, GENESIS_TIME - BLOCK_TIME, BLOCK1_BITS, parent.height, max(parent.time, t - HALF_LIFE), BLOCK_TIME, HALF_LIFE, BLOCK1_BITS)


def pick_time_bits(parent, now):
    t = max(now, parent.time + 1)
    return t, pick_bits(parent, t)


def block_work(bits):
    return (1 << 256) // (bits_to_target(bits) + 1)


# --- body: parsing and applying records ---

NUM = rb'(0|[1-9][0-9]{0,17})'
VALUE_RE = re.compile(rb'\{"balance":' + NUM + rb'[,}]')
CONST_RE = re.compile(rb'\{"balance":' + NUM + rb',"byte_cost":' + NUM + rb'[,}]')


def check_value(v):
    if not v.endswith(b'\n') or VALUE_RE.match(v) is None:
        raise Invalid('contract value does not start with {"balance":<number> or does not end with LF')


def value_balance(v):
    return int(VALUE_RE.match(v).group(1))


def constitution_byte_cost(state):
    m = CONST_RE.match(state.get(b'constitution', b''))
    if m is None:
        raise Invalid('constitution missing or malformed')
    return int(m.group(2))


def parse_num(tok):
    if not tok or not tok.isdigit() or (tok[0] == 0x30 and len(tok) > 1) or len(tok) > 8:
        raise Invalid('bad length')
    return int(tok)


def parse_body(body):
    if b'\r' in body or b'\x00' in body:
        raise Invalid('body has a CR or NUL byte')
    try:
        body.decode('utf-8')
    except UnicodeDecodeError:
        raise Invalid('body is not UTF-8')
    n = len(body)
    pos = 0
    recs = []

    def take(length):
        nonlocal pos
        if length < 1 or pos + length > n:
            raise Invalid('text runs past the end of the body or has length 0')
        t = body[pos : pos + length]
        if t[-1] != 10:
            raise Invalid('text does not end with LF')
        pos += length
        return t

    while pos < n:
        nl = body.find(b'\n', pos)
        if nl < 0:
            raise Invalid('record line has no LF')
        parts = body[pos:nl].split(b' ')
        pos = nl + 1
        kind = parts[0]
        if kind == b'message' and len(parts) == 2:
            recs.append((b'message', take(parse_num(parts[1]))))
        elif kind == b'contract' and len(parts) == 3:
            il = parse_num(parts[1])
            vl = parse_num(parts[2])
            idt = take(il)
            val = take(vl) if vl > 0 else None
            recs.append((b'contract', idt, val))
        elif kind == b'edit' and len(parts) == 4:
            il = parse_num(parts[1])
            fl = parse_num(parts[2])
            rl = parse_num(parts[3])
            idt = take(il)
            find = take(fl)
            rep = take(rl)
            recs.append((b'edit', idt, find, rep))
        elif kind == b'undo' and len(parts) == 3 and re.fullmatch(rb'[0-9a-f]{64}', parts[1]):
            recs.append((b'undo', take(parse_num(parts[2])), parts[1].decode()))
        else:
            raise Invalid('unknown record')
    return recs


def apply_records(state, recs, before=None):
    """before(block id, contract id) gives a contract's value just before that block, for undo records."""
    touched = set()
    for rec in recs:
        kind = rec[0]
        if kind == b'message':
            continue
        cid = rec[1][:-1]
        if kind == b'undo':
            if before is None:
                raise Invalid('an undo needs the chain it sits on')
            val = before(rec[2], cid)
            if val is None:
                state.pop(cid, None)
                touched.discard(cid)
                continue
            state[cid] = val
        elif kind == b'contract':
            val = rec[2]
            if val is None:
                if cid not in state:
                    raise Invalid('cannot remove %s: it does not exist' % show(cid))
                del state[cid]
                touched.discard(cid)
                continue
            check_value(val)
            state[cid] = val
        else:
            if cid not in state:
                raise Invalid('cannot edit %s: it does not exist' % show(cid))
            find = rec[2][:-1]
            rep = rec[3][:-1]
            if not find:
                raise Invalid('edit find text is empty')
            v = state[cid]
            i = v.find(find)
            if i < 0:
                raise Invalid('edit find text not found in %s' % show(cid))
            if v.find(find, i + 1) >= 0:
                raise Invalid('edit find text occurs more than once in %s' % show(cid))
            nv = v[:i] + rep + v[i + len(find) :]
            check_value(nv)
            state[cid] = nv
        touched.add(cid)
    return touched


def apply_and_check(pstate, body, before=None):
    recs = parse_body(body)
    byte_cost = constitution_byte_cost(pstate)
    state = dict(pstate)
    touched = apply_records(state, recs, before)
    if CONST_RE.match(state.get(b'constitution', b'')) is None:
        raise Invalid('constitution must exist and start with {"balance":<number>,"byte_cost":<number>')
    byte_cost = min(byte_cost, constitution_byte_cost(state))  # so a block can undo a cost set too high to build on
    for cid in touched:
        v = state.get(cid)
        if v is None:
            continue
        need = byte_cost * (len(cid) + 1 + len(v))
        if value_balance(v) < need:
            raise Invalid('contract %s has balance %d but needs %d to cover its space' % (show(cid), value_balance(v), need))
    return state, state_root(state)


# --- state root ---

ZERO32 = bytes(32)


def _root(items, lo, hi, depth):
    n = hi - lo
    if n == 0:
        return ZERO32
    if n == 1:
        return items[lo][1]
    if depth >= 256:
        raise Invalid('two contracts with the same id hash')
    a = _split(items, lo, hi, depth)
    return sha256(b'\x01' + _root(items, lo, a, depth + 1) + _root(items, a, hi, depth + 1))


def _split(items, lo, hi, depth):
    """Items are sorted by key, so the first one whose bit at this depth is 1 splits them."""
    byte = depth >> 3
    mask = 0x80 >> (depth & 7)
    a, b = lo, hi
    while a < b:
        m = (a + b) // 2
        if items[m][0][byte] & mask:
            b = m
        else:
            a = m + 1
    return a


def state_root(state):
    items = []
    for cid, val in state.items():
        k = sha256(cid)
        items.append((k, sha256(b'\x00' + k + sha256(val))))
    items.sort()
    return _root(items, 0, len(items), 0)


# --- proofs: the same tree kept whole, to show the path to one contract ---


def _tree(items, lo, hi, depth):
    """A node is None if empty, (key, hash, value hash) for one contract and otherwise (left, hash, right)."""
    if lo == hi:
        return None
    if hi - lo == 1:
        return items[lo]
    if depth >= 256:
        raise Invalid('two contracts with the same id hash')
    a = _split(items, lo, hi, depth)
    left, right = _tree(items, lo, a, depth + 1), _tree(items, a, hi, depth + 1)
    return (left, sha256(b'\x01' + (left[1] if left else ZERO32) + (right[1] if right else ZERO32)), right)


def state_tree(state):
    items = []
    for cid, val in state.items():
        k, v = sha256(cid), sha256(val)
        items.append((k, sha256(b'\x00' + k + v), v))
    items.sort()
    return _tree(items, 0, len(items), 0)


def _bit(key, depth):
    return key[depth >> 3] & (0x80 >> (depth & 7))


def tree_path(tree, key):
    """The hashes beside the way down to where this key belongs, from the top, and what's there."""
    path, node, depth = [], tree, 0
    while node is not None and not isinstance(node[0], bytes):
        near, far = (node[2], node[0]) if _bit(key, depth) else (node[0], node[2])
        path.append(far[1] if far else ZERO32)
        node, depth = near, depth + 1
    return path, node


def check_path(cid, value, other, path, root):
    """Whether this path shows that the contract has this value, or with no value that it doesn't exist."""
    key = sha256(cid)
    if len(path) > 256 or any(len(x) != 32 for x in path):
        return False
    if value is not None:
        node = sha256(b'\x00' + key + sha256(value))
    elif other is not None:
        other_key, other_value = other
        if len(other_key) != 32 or len(other_value) != 32 or other_key == key:
            return False
        if any(bool(_bit(other_key, d)) != bool(_bit(key, d)) for d in range(len(path))):
            return False
        node = sha256(b'\x00' + other_key + other_value)
    else:
        node = ZERO32
    for depth in range(len(path) - 1, -1, -1):
        node = sha256(b'\x01' + path[depth] + node) if _bit(key, depth) else sha256(b'\x01' + node + path[depth])
    return node == root


# --- blocks ---

HEX_LOWER = re.compile(rb'[0-9a-f]*')


class BlockInfo:
    __slots__ = ('id', 'parent', 'height', 'time', 'bits', 'cumwork', 'state_root', 'wire', 'body', 'verdict', 'reason', 'ok', 'seen', 'changes', 'flag')


def parse_wire(data):
    if len(data) > MAX_BLOCK:
        raise Invalid('block is over 64 KiB')
    i = data.find(b'\n')
    if i < 0 or not data.startswith(b'header '):
        raise Invalid('no header line')
    hx = data[7:i]
    if len(hx) != 160 or not HEX_LOWER.fullmatch(hx):
        raise Invalid('header is not 160 lowercase hex digits')
    j = data.find(b'\n', i + 1)
    if j < 0 or not data.startswith(b'coinbase ', i + 1):
        raise Invalid('no coinbase line')
    cx = data[i + 10 : j]
    if not cx or len(cx) % 2 or not HEX_LOWER.fullmatch(cx):
        raise Invalid('coinbase is not lowercase hex')
    if data[j + 1 : j + 2] != b'\n':
        raise Invalid('no empty line after the coinbase')
    return bytes.fromhex(hx.decode()), bytes.fromhex(cx.decode()), data[j + 2 :]


def push_height(h):
    b = bytearray()
    x = h
    while x:
        b.append(x & 0xff)
        x >>= 8
    if not b:
        b = bytearray(b'\x00')
    if b[-1] & 0x80:
        b.append(0)
    return bytes([len(b)]) + bytes(b)


def build_coinbase(height, extra, root, body):
    script = push_height(height) + extra
    if not 2 <= len(script) <= 100:
        raise Invalid('coinbase script must be 2 to 100 bytes')
    return (
        b'\x01\x00\x00\x00' + b'\x01' + bytes(32) + b'\xff\xff\xff\xff'
        + bytes([len(script)]) + script + b'\xff\xff\xff\xff'
        + b'\x01' + bytes(8) + bytes([77]) + b'\x6a\x4b' + b'commonchain' + root + sha256(body)
        + bytes(4)
    )


def check_coinbase(cb, height, root, body):
    if len(cb) < 139 or len(cb) > 237:
        raise Invalid('coinbase has the wrong size')
    size = cb[41]
    if not 2 <= size <= 100 or len(cb) != 137 + size:
        raise Invalid('coinbase script length is wrong')
    script = cb[42 : 42 + size]
    push = push_height(height)
    if script[: len(push)] != push:
        raise Invalid('coinbase script does not start with the height push')
    payload = cb[58 + size : 133 + size]
    if payload[:11] != b'commonchain':
        raise Invalid('coinbase tag is not commonchain')
    if payload[11:43] != root:
        raise Invalid('state root in the coinbase is not the state after the body')
    if payload[43:75] != sha256(body):
        raise Invalid('body hash in the coinbase is not the sha256 of the body')
    if cb != build_coinbase(height, script[len(push) :], root, body):
        raise Invalid('coinbase is not of the exact form')


def block_id(h):
    return sha256d(h)[::-1].hex()


def validate_block(h, cb, body, parent, pstate, before=None):
    _version, _prev, merkle, btime, bits, _nonce = struct.unpack('<I32s32sIII', h)
    height = parent.height + 1
    if btime <= parent.time:
        raise Invalid('time is not after the parent time')
    if bits != pick_bits(parent, btime):
        raise Invalid('bits are not what the target rule gives')
    if int.from_bytes(sha256d(h), 'little') > bits_to_target(bits):
        raise Invalid('hash is above the target')
    if merkle != sha256d(cb):
        raise Invalid('merkle root is not the sha256d of the coinbase')
    state, root = apply_and_check(pstate, body, before)
    check_coinbase(cb, height, root, body)
    info = BlockInfo()
    named = {rec[1][:-1] for rec in parse_body(body) if rec[0] != b'message'}
    info.changes = {cid: pstate.get(cid) for cid in named if pstate.get(cid) != state.get(cid)}
    info.id = block_id(h)
    info.parent = parent.id
    info.height = height
    info.time = btime
    info.bits = bits
    info.cumwork = parent.cumwork + block_work(bits)
    info.state_root = root
    info.body = body
    return info, state


# --- what code understands on its own ---


def strict_json(raw):
    def hook(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError('duplicate key')
        return dict(pairs)

    return json.loads(raw.decode('utf-8'), object_pairs_hook=hook)


def plain_int(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0


def parse_payment(text, pstate):
    """A signed payment in the wallet type's form, or None. Checks the signature and the sender's state."""
    i = text.find(b'\nsig ')
    if i < 0:
        return None
    signed, rest = text[: i + 1], text[i + 1 :]
    lines = rest.rstrip(b'\n').split(b'\n')
    if len(lines) != 1:
        return None
    parts = lines[0].split(b' ')
    if len(parts) != 3:
        return None
    try:
        m = strict_json(signed)
        pub, sig = bytes.fromhex(parts[1].decode()), bytes.fromhex(parts[2].decode())
    except ValueError:
        return None
    if not isinstance(m, dict) or set(m) - {'from', 'to', 'amount', 'fee', 'nonce'}:
        return None
    sender, to, amount, fee, nonce = m.get('from'), m.get('to'), m.get('amount'), m.get('fee', 0), m.get('nonce')
    if not (isinstance(sender, str) and isinstance(to, str) and plain_int(amount) and plain_int(fee) and plain_int(nonce)) or amount < 1 or sender == to:
        return None
    old = pstate.get(sender.encode())
    if old is None:
        return None
    try:
        wallet = strict_json(old)
    except ValueError:
        return None
    if not isinstance(wallet, dict) or wallet.get('type') != 'wallet' or wallet.get('owner') != parts[1].decode():
        return None
    if nonce != wallet.get('nonce', 0) + 1 or wallet['balance'] < amount + fee or not verify(pub, signed, sig):
        return None
    return {'from': sender, 'to': to, 'amount': amount, 'fee': fee, 'nonce': nonce}


NEW_WALLET_KEYS = {'balance', 'type', 'owner', 'nonce', 'name'}


def routine(pstate, state, recs, height, is_real_reward):
    """(True, why) only for blocks code fully understands: rewards, payouts of rewards that have come due, signed
    payments and one-step votes. Anything else wants reading. It says nothing about which chain to follow."""
    paid, got, payers, fees = {}, {}, {}, 0
    for rec in recs:
        if rec[0] == b'undo':
            return False, 'undoes a change from block %s' % rec[2][:16]
        if rec[0] == b'message':
            pay = parse_payment(rec[1], pstate)
            if pay:
                if pay['from'] in payers:
                    return False, 'two payments from one wallet'
                payers[pay['from']] = pay['nonce']
                paid[pay['from']] = paid.get(pay['from'], 0) + pay['amount'] + pay['fee']
                got[pay['to']] = got.get(pay['to'], 0) + pay['amount']
                fees += pay['fee']
    cost, released, reward, extra = constitution_byte_cost(pstate), 0, 0, 0
    for cid, old in pstate.items():
        if cid not in state:
            try:
                rj = strict_json(old)
            except ValueError:
                return False, 'removes %s' % show(cid)
            if not isinstance(rj, dict) or rj.get('type') != 'reward' or not plain_int(rj.get('unlocks')) or rj['unlocks'] > height or not isinstance(rj.get('owner'), str):
                return False, 'removes %s' % show(cid)
            if not is_real_reward(cid, old):
                return False, 'pays out %s, which the block at that height did not create' % show(cid)
            pay_out = max(rj['balance'] - cost * (len(cid) + 1 + len(old)), 0)
            if pay_out:
                got[rj['owner']] = got.get(rj['owner'], 0) + pay_out
            released += rj['balance'] - pay_out
    for cid in sorted(set(pstate) | set(state)):
        old, new = pstate.get(cid), state.get(cid)
        if old == new or new is None:
            continue
        try:
            nj = strict_json(new)
        except ValueError:
            return False, '%s is not plain JSON' % show(cid)
        if not isinstance(nj, dict):
            return False, '%s is not a JSON object' % show(cid)
        if cid == b'constitution':
            if old is None or not one_vote(old, nj):
                return False, 'changes the constitution'
            continue
        name = cid.decode('utf-8', 'replace')
        if cid == b'reward/%d' % height:
            if set(nj) != {'balance', 'type', 'owner', 'unlocks'} or nj['type'] != 'reward' or nj['unlocks'] != height + REWARD_LOCK or not isinstance(nj['owner'], str):
                return False, 'its reward contract has an unusual form'
            reward = nj['balance']
            continue
        if nj.get('type') != 'wallet':
            return False, 'changes %s, which is not a wallet' % show(cid)
        if old is None:
            if set(nj) - NEW_WALLET_KEYS or nj.get('nonce', 0) != 0 or nj.get('owner') != name or not re.fullmatch(r'[0-9a-f]{64}', name):
                return False, 'new contract %s is not a plain wallet' % show(cid)
            before, was = 0, 0
        else:
            try:
                oj = strict_json(old)
            except ValueError:
                return False, '%s was not plain JSON' % show(cid)
            if not isinstance(oj, dict) or oj.get('type') != 'wallet':
                return False, 'changes %s, which is not a wallet' % show(cid)
            if {k: v for k, v in oj.items() if k not in ('balance', 'nonce')} != {k: v for k, v in nj.items() if k not in ('balance', 'nonce')}:
                return False, 'changes more than the balance and nonce of %s' % show(cid)
            before, was = oj['balance'], oj.get('nonce', 0)
        after = nj['balance']
        if name in payers:
            if nj.get('nonce') != payers[name]:
                return False, 'wrong nonce on %s' % show(cid)
        elif nj.get('nonce', 0) != was:
            return False, 'changes the nonce of %s with no payment' % show(cid)
        surplus = after - before - got.get(name, 0) + paid.get(name, 0)
        if surplus < 0:
            return False, 'takes tokens from %s without a signature' % show(cid)
        extra += surplus
    for name in got:
        if name.encode() not in state:
            return False, 'pays a contract that does not exist'
    if extra > released:  # a miner may keep what the space it frees releases, in a wallet or in its reward
        return False, 'credits %d tokens to wallets with no payment behind them' % extra
    if reward + extra > REWARD + fees + released:
        return False, 'rewards itself %d tokens, more than the reward, fees and released space' % (reward + extra)
    return True, 'routine'


def one_vote(old, nj):
    try:
        oj = strict_json(old)
    except ValueError:
        return False
    if not isinstance(oj, dict) or not isinstance(oj.get('proposals'), dict) or not isinstance(nj.get('proposals'), dict):
        return False
    if {k: v for k, v in oj.items() if k != 'proposals'} != {k: v for k, v in nj.items() if k != 'proposals'}:
        return False
    before, after = oj['proposals'], nj['proposals']
    if set(before) != set(after):
        return False
    changed = [k for k in before if before[k] != after[k]]
    return len(changed) == 1 and plain_int(before[changed[0]]) and after[changed[0]] == before[changed[0]] + 1


# --- chain store ---


class Chain:
    STATE_CACHE = 64

    def __init__(self, datadir, genesis_state, genesis_root):
        self.lock = threading.RLock()
        self.datadir = datadir
        g = BlockInfo()
        g.id = genesis_root
        g.parent = None
        g.height = 0
        g.time = GENESIS_TIME
        g.bits = None
        g.cumwork = 0
        g.state_root = bytes.fromhex(genesis_root)
        g.wire = None
        g.body = None
        g.verdict = 'accept'
        g.reason = 'genesis'
        g.ok = True
        g.seen = 0
        g.changes = {}
        g.flag = None
        self.blocks = {g.id: g}
        self.genesis = g
        self.genesis_state = genesis_state
        self.best = g
        self.version = 0
        self.cache = OrderedDict()
        self.trees = OrderedDict()
        self.proposal = None
        self.undos = []
        self.trouble = ''
        self.undos_path = os.path.join(datadir, 'undos.json')
        if os.path.exists(self.undos_path):
            with open(self.undos_path, encoding='utf-8') as f:
                for u in json.load(f):
                    u['left'] = [c.encode('utf-8') for c in u['left']]
                    u['orig'] = [c.encode('utf-8') for c in u['orig']]
                    self.undos.append(u)
        self.pool = OrderedDict()
        self.pool_seq = 0
        self.logf = None
        self.read_path = os.path.join(datadir, 'read.json')
        self.cleared = set()
        if os.path.exists(self.read_path):
            with open(self.read_path, encoding='utf-8') as f:
                self.cleared = set(json.load(f))
        self._load(os.path.join(datadir, 'blocks.dat'))

    def _load(self, path):
        count = good = 0
        if os.path.exists(path):
            with open(path, 'rb') as f:
                data = f.read()
            pos = 0
            while pos < len(data):
                nl = data.find(b'\n', pos)
                if nl < 0:
                    break
                try:
                    ln = int(data[pos:nl])
                except ValueError:
                    break
                wire = data[nl + 1 : nl + 1 + ln]
                if len(wire) != ln:
                    break
                ok, why = self.add_block(wire, persist=False, own=True, replay=True)
                if ok:
                    count += 1
                else:
                    log('stored block refused on reload: %s' % why)
                pos = nl + 1 + ln
                good = pos
            if good < len(data):
                with open(path, 'r+b') as f:
                    f.truncate(good)
        self.logf = open(path, 'ab')
        log('loaded %d blocks, tip %d %s' % (count, self.best.height, self.best.id))

    def get_state(self, info):
        with self.lock:
            if info.id == self.genesis.id:
                return self.genesis_state
            st = self.cache.get(info.id)
            if st is not None:
                return st
            path = []
            cur = info
            while cur.id != self.genesis.id and cur.id not in self.cache:
                path.append(cur)
                cur = self.blocks[cur.parent]
            st = self.genesis_state if cur.id == self.genesis.id else self.cache[cur.id]
            for b in reversed(path):
                st, _ = apply_and_check(st, b.body, self.undo_lookup(self.blocks[b.parent], st))
                self._remember(b.id, st)
            return st

    def undo_lookup(self, parent, pstate):
        """For a block on top of this parent: a contract's value just before one of the blocks it may undo."""
        recent, index = [], {}

        def before(bid, cid):
            if not recent:
                cur = parent
                while cur.height > 0 and len(recent) < UNDO_WINDOW:
                    index[cur.id] = len(recent)
                    recent.append(cur)
                    cur = self.blocks[cur.parent]
            i = index.get(bid)
            if i is None:
                raise Invalid('an undo names a block that is not one of the last %d on its chain' % UNDO_WINDOW)
            for b in reversed(recent[: i + 1]):
                if cid in b.changes:
                    return b.changes[cid]
            return pstate.get(cid)

        return before

    def _remember(self, bid, state):
        self.cache[bid] = state
        self.cache.move_to_end(bid)
        while len(self.cache) > self.STATE_CACHE:
            self.cache.popitem(last=False)

    def proof(self, cid, bid=None):
        """A proof at my tip, or at a block whose state I still have, so old blocks can't be used to make me replay."""
        with self.lock:
            b = self.blocks.get(bid) if bid else self.best
            if b is None or (bid and b is not self.genesis and b.id not in self.cache):
                return None
            state = self.get_state(b)
            tree = self.trees.get(b.id)
            if tree is None:
                tree = state_tree(state)
                self.trees[b.id] = tree
                while len(self.trees) > 2:
                    self.trees.popitem(last=False)
            path, node = tree_path(tree, sha256(cid))
            value = state.get(cid)
            p = {'block': b.id, 'height': b.height, 'root': b.state_root.hex(), 'id': cid.decode('utf-8'),
                 'value': None if value is None else value.decode('utf-8'), 'path': [x.hex() for x in path]}
            if value is None and node is not None:
                p['other'] = {'key': node[0].hex(), 'value_hash': node[2].hex()}
            if b.wire is not None:
                h, cb, _body = parse_wire(b.wire)
                p['header'], p['coinbase'] = h.hex(), cb.hex()
            return p

    def _place(self, info, pstate, state, own, replay):
        """Every valid block counts, unless it's dated too far ahead. Wanting a read doesn't change that."""
        if own and not replay:
            info.flag = None
            self.cleared.add(info.id)  # so a restart doesn't ask me to read my own blocks
            with open(self.read_path, 'w', encoding='utf-8') as f:
                json.dump(sorted(self.cleared), f)
            return 'accept', 'mined here'
        parent = self.blocks[info.parent]
        ok, why = routine(pstate, state, parse_body(info.body), info.height, lambda cid, value: self.is_real_reward(parent, cid, value))
        info.flag = None if ok or info.id in self.cleared else why
        if info.time > time.time() + FUTURE_GRACE:
            return 'wait', 'dated ahead of the clock'
        return 'accept', why

    def add_block(self, wire, persist=True, own=False, replay=False, force=False):
        """force takes a block that's part of a heavier chain, however far behind my tip it starts."""
        with self.lock:
            try:
                h, cb, body = parse_wire(wire)
                bid = block_id(h)
                if bid in self.blocks:
                    return True, 'known'
                parent_hex = h[4:36][::-1].hex()
                parent = self.blocks.get(parent_hex)
                if parent is None:
                    return False, 'unknown parent %s' % parent_hex
                bits = struct.unpack('<I', h[72:76])[0]
                if not replay and not force and self.best.bits is not None:
                    margin = BEHIND_BLOCKS * block_work(self.best.bits)
                    if parent.cumwork + block_work(bits) + margin < self.best.cumwork:
                        return False, 'too far behind to catch up'
                pstate = self.get_state(parent)
                info, state = validate_block(h, cb, body, parent, pstate, self.undo_lookup(parent, pstate))
            except Invalid as e:
                return False, str(e)
            info.wire = wire
            info.seen = time.time()
            info.verdict, info.reason = self._place(info, pstate, state, own, replay)
            info.ok = parent.ok and info.verdict == 'accept'
            self.blocks[bid] = info
            self._remember(bid, state)
            if persist and self.logf:
                self.logf.write(b'%d\n' % len(wire) + wire)
                self.logf.flush()
            self.refresh_best()
            for rec in parse_body(body):
                if rec[0] == b'message':
                    self.pool.pop(sha256(rec[1]).hex(), None)
                elif rec[0] == b'undo':  # once done it's done, whatever later blocks do to that contract
                    for u in self.undos:
                        if u['block'] == rec[2] and rec[1][:-1] in u['left']:
                            u['left'].remove(rec[1][:-1])
            before_count = [(u['done_in'], len(u['left'])) for u in self.undos]
            for u in self.undos:
                if not u['done_in'] and u.get('part') and u['part'] in body:
                    u['take'], u['trim'], u['part'] = False, None, None  # taken once is enough
                    if not u['left']:
                        u['done_in'] = bid  # it stays on the list until that block is buried
            self.undos = [u for u in self.undos if u['done_in'] or u['left'] or u['take'] or u['trim']]
            if not replay and before_count != [(u['done_in'], len(u['left'])) for u in self.undos]:
                self.save_undos()
            if self.proposal and self.proposal in body:
                self.proposal = None
            if not replay:
                log('block %d %s %s: %s' % (info.height, bid[:16], info.verdict, info.reason))
            return True, 'accepted' if info.verdict == 'accept' else 'waiting'

    def refresh_best(self):
        for b in self.blocks.values():
            if b.parent is not None:
                b.ok = self.blocks[b.parent].ok and b.verdict == 'accept'
        heaviest = self.best if self.best.ok else self.genesis
        for b in self.blocks.values():
            if b.ok and b.cumwork > heaviest.cumwork:
                heaviest = b
        if heaviest is not self.best:
            self.best = heaviest
            self.version += 1

    def is_real_reward(self, tip, cid, value):
        """Whether the block at the height in this reward contract's id, on this chain, wrote exactly this value.
        Anyone can write a contract that looks like a reward that has come due, or squat on a future one's id."""
        if not cid.startswith(b'reward/') or not cid[7:].isdigit():
            return False
        height, cur = int(cid[7:]), tip
        if cid != b'reward/%d' % height or height < 1 or height > tip.height or tip.height - height > UNDO_WINDOW:
            return False
        while cur.height > height:
            cur = self.blocks[cur.parent]
        return any(rec[0] == b'contract' and rec[1][:-1] == cid and rec[2] == value for rec in parse_body(cur.body))

    def clear_flag(self, bid):
        """The agent or person has read this block and found it reasonable."""
        with self.lock:
            b = self.blocks.get(bid)
            if b is None:
                return False
            b.flag = None
            self.cleared.add(bid)
            with open(self.read_path, 'w', encoding='utf-8') as f:
                json.dump(sorted(self.cleared), f)
            return True

    def save_undos(self):
        with open(self.undos_path + '.new', 'w', encoding='utf-8') as f:
            json.dump([dict({k: v for k, v in u.items() if k != 'part'}, left=[c.decode('utf-8') for c in u['left']], orig=[c.decode('utf-8') for c in u['orig']]) for u in self.undos], f)
        os.replace(self.undos_path + '.new', self.undos_path)

    def settle_undo(self, u):
        """A correction that has gone in stays on the list until its block is buried. If a heavier chain has dropped
        that block, it needs doing again, which is what this returns."""
        done, cur = self.blocks.get(u['done_in']), self.best
        if done is not None:
            while cur.height > done.height:
                cur = self.blocks[cur.parent]
        if cur is done:
            if self.best.height - done.height >= 6:
                self.undos.remove(u)
                self.save_undos()
            return False
        u.update(left=list(u['orig']), take=u['orig_take'], trim=u['orig_trim'], done_in=None, part=None)
        self.save_undos()
        return True

    def add_undo(self, req):
        """A correction the agent or person has decided on. It goes in the next block mined here, and stays on the
        list through new blocks, heavier chains and restarts until it's buried."""
        with self.lock:
            b = self.blocks.get(req['block'])
            why = req['why'].strip()
            if b is None:
                return 'refused: I do not know that block'
            if not why or '\r' in why or '\x00' in why:
                return 'refused: an undo needs a reason, with no CR or NUL'
            try:
                self.undo_lookup(self.best, self.get_state(self.best))(b.id, b'')
            except Invalid as e:
                return 'refused: %s' % e
            reward = b'reward/%d' % b.height
            trim = req.get('trim') or None
            left = [c.encode('utf-8') for c in req.get('contracts', [])]
            if not left and not trim:
                left = [c for c in sorted(b.changes) if c != reward]
            if req.get('take') and b.changes.get(reward, b'') is None:  # only if that block is what created its reward
                left = [reward] + [c for c in left if c != reward]
            if not left and not trim:
                return 'refused: there is nothing in that block to undo'
            take = bool(req.get('take'))
            self.undos.append({'block': b.id, 'left': left, 'orig': list(left), 'why': why, 'take': take, 'orig_take': take, 'trim': trim, 'orig_trim': trim, 'done_in': None})
            self.save_undos()
            self.clear_flag(b.id)
            return 'ok: it goes in the next block mined here'

    def drop_item(self, prefix):
        with self.lock:
            gone = [k for k in self.pool if k.startswith(prefix)] if prefix else []
            for k in gone:
                del self.pool[k]
            return len(gone)

    def recheck_future(self):
        with self.lock:
            changed = False
            for b in self.blocks.values():
                if b.verdict == 'wait' and b.time <= time.time() + FUTURE_GRACE:
                    p = self.blocks[b.parent]
                    pstate = self.get_state(p)
                    b.verdict, b.reason = self._place(b, pstate, self.get_state(b), False, False)
                    changed = True
            if changed:
                self.refresh_best()

    def waiting(self):
        return [b for b in self.blocks.values() if b.verdict == 'wait']

    def to_read(self):
        """Blocks on my chain that code doesn't fully understand, recent enough to undo with an undo record."""
        out, cur = [], self.best
        for _ in range(UNDO_WINDOW):
            if cur.height == 0:
                break
            if cur.flag:
                out.append(cur)
            cur = self.blocks[cur.parent]
        out.reverse()
        return out

    def tips(self):
        parents = {b.parent for b in self.blocks.values()}
        return [b for b in self.blocks.values() if b.id not in parents]

    def chain_ids(self):
        out = []
        cur = self.best
        while cur.height > 0:
            out.append((cur.height, cur.id))
            cur = self.blocks[cur.parent]
        out.reverse()
        return out

    def add_item(self, text):
        with self.lock:
            if len(text) > MAX_ITEM or b'\x00' in text or b'\r' in text:
                return False, 'too long, or has a CR or NUL byte'
            try:
                text.decode('utf-8')
            except UnicodeDecodeError:
                return False, 'not UTF-8'
            if not text.endswith(b'\n'):
                text += b'\n'
            key = sha256(text).hex()
            if key not in self.pool:
                self.pool_seq += 1
                self.pool[key] = (self.pool_seq, text, time.time())
                while len(self.pool) > MAX_POOL:
                    self.pool.popitem(last=False)
            return True, key


# --- writing blocks ---


def message_record(text):
    return b'message %d\n%s' % (len(text), text)


def contract_record(cid, value):
    idt = cid + b'\n'
    return b'contract %d %d\n%s%s' % (len(idt), len(value), idt, value)


def dump_value(obj):
    return json.dumps(obj, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'


def undo_record(bid, cid):
    idt = cid + b'\n'
    return b'undo %s %d\n%s' % (bid.encode(), len(idt), idt)


def clawback(b, state):
    """A block's reward that has already been paid out: what can be taken back from its miner's contract, and the
    record that does it. That contract keeps enough to cover its space."""
    for rec in parse_body(b.body):
        if rec[0] == b'contract' and rec[1][:-1] == b'reward/%d' % b.height and rec[2]:
            try:
                j = strict_json(rec[2])
            except ValueError:
                return 0, b''
            owner = j.get('owner').encode('utf-8') if isinstance(j, dict) and isinstance(j.get('owner'), str) else None
            old = state.get(owner)
            if old is None:
                return 0, b''
            amount = min(j['balance'], value_balance(old) - constitution_byte_cost(state) * (len(owner) + 1 + len(old)))
            if amount <= 0:
                return 0, b''
            m = VALUE_RE.match(old)
            return amount, contract_record(owner, b'{"balance":%d' % (int(m.group(1)) - amount) + old[m.end() - 1 :])
    return 0, b''


def undo_part(chain, u, state, before):
    """The message and records for one undo, and what it takes from the block's miner. None if there's nothing left
    to do. A block's reward stays out of it unless it's being taken, since not every mistake deserves a penalty."""
    b = chain.blocks[u['block']]
    reward = b'reward/%d' % b.height
    u['left'] = [c for c in u['left'] if before(b.id, c) != state.get(c)]
    todo = u['left'][:300]
    taken, claw = 0, b''
    if u['take'] and reward in todo:
        taken = value_balance(state[reward])
    elif u['take']:
        taken, claw = clawback(b, state)
    if u['trim']:  # a set number of tokens off a contract, from whatever it holds by the time this is mined
        cid, old = u['trim'][0].encode('utf-8'), state.get(u['trim'][0].encode('utf-8'))
        if old is not None:
            m = VALUE_RE.match(old)
            cut = min(u['trim'][1], int(m.group(1)) - constitution_byte_cost(state) * (len(cid) + 1 + len(old)))
            if cut > 0:
                claw += contract_record(cid, b'{"balance":%d' % (int(m.group(1)) - cut) + old[m.end() - 1 :])
    if not todo and not claw:
        return None, 0
    text = '%s block %d %s: %s\n' % ('Undoing' if todo else 'Correcting', b.height, b.id, u['why'])
    if taken:
        text += 'Taking its reward of %d.\n' % taken
    return message_record(text.encode('utf-8')) + b''.join(undo_record(b.id, c) for c in todo) + claw, taken


def credit(old, owner, amount):
    """The owner's contract with more tokens in it, or a new wallet if it has none yet."""
    if old is None:
        return dump_value({'balance': amount, 'type': 'wallet', 'owner': owner.decode('utf-8', 'replace'), 'nonce': 0})
    m = VALUE_RE.match(old)
    return b'{"balance":%d' % (int(m.group(1)) + amount) + old[m.end() - 1 :]


def payouts(chain, state, height, unread):
    """Up to 8 real reward contracts that have come due, oldest first: (id, its value as JSON). None that a block
    still to be read has touched, and none whose owner can't be a contract id."""
    due = []
    for cid in state:
        if not cid.startswith(b'reward/') or not cid[7:].isdigit() or cid in unread:
            continue
        try:
            rj = strict_json(state[cid])
        except ValueError:
            continue
        if not isinstance(rj, dict) or rj.get('type') != 'reward' or not plain_int(rj.get('unlocks')) or rj['unlocks'] > height or not isinstance(rj.get('owner'), str):
            continue
        if re.search('[\r\x00]', rj['owner']) or not 0 < len(rj['owner']) <= 200 or rj['owner'].encode('utf-8') in unread:
            continue
        if not chain.is_real_reward(chain.best, cid, state[cid]):
            continue
        due.append((int(cid[7:]), cid, rj))
    return [(cid, rj) for _, cid, rj in sorted(due, key=lambda x: x[0])[:8]]


def build_body(chain, key, plain=False):
    """The next block for this miner: undos decided on here, the agent's proposal, pending signed payments, rewards
    that have come due, a little of what people have said, then this block's reward. Plain means the reward alone."""
    with chain.lock:
        height = chain.best.height + 1
        pstate = chain.get_state(chain.best)
        before = chain.undo_lookup(chain.best, pstate)
        parts, state, extra, used = [], dict(pstate), 0, set()
        for u in [] if plain else list(chain.undos):
            if u['done_in'] and not chain.settle_undo(u):
                continue
            try:
                part, taken = undo_part(chain, u, state, before)
                if part is None:
                    chain.undos.remove(u)
                    chain.save_undos()
                    continue
                if sum(len(p) for p in parts) + len(part) > 30000:
                    break
                apply_records(state, parse_body(part), before)
            except (Invalid, KeyError) as e:
                chain.trouble = 'dropped a correction to block %s: %s' % (u['block'][:16], e)
                log(chain.trouble)
                chain.undos.remove(u)
                chain.save_undos()
                continue
            u['part'] = part
            parts.append(part)
            extra += taken
        if chain.proposal and not plain:
            try:
                state, _ = apply_and_check(state, chain.proposal, before)
                parts.append(chain.proposal)
            except Invalid as e:
                chain.trouble = 'dropped the proposal: %s' % e
                log(chain.trouble)
                chain.proposal = None
        fees = 0
        size = sum(len(p) for p in parts)
        unread = set()  # tokens touched by a block nobody has read yet shouldn't move on before someone does
        for b in chain.to_read():
            unread.update(b.changes)
        for mid, (_seq, text, _seen) in [] if plain else list(chain.pool.items()):
            if size > 40000:
                break
            pay = parse_payment(text, state)
            if not pay or pay['from'].encode() in unread or pay['to'].encode() in unread:
                continue
            sender, to = pay['from'].encode(), pay['to'].encode()
            sj = strict_json(state[sender])
            sj['balance'] -= pay['amount'] + pay['fee']
            sj['nonce'] = pay['nonce']
            if to in state:
                try:
                    tj = strict_json(state[to])
                except ValueError:
                    continue
                if not isinstance(tj, dict) or tj.get('type') != 'wallet':
                    continue
                tj['balance'] += pay['amount']
            elif re.fullmatch(r'[0-9a-f]{64}', pay['to']):
                tj = {'balance': pay['amount'], 'type': 'wallet', 'owner': pay['to'], 'nonce': 0}
            else:
                continue
            sv, tv = dump_value(sj), dump_value(tj)
            if not (sv.startswith(b'{"balance":') and tv.startswith(b'{"balance":')):
                continue
            cost = constitution_byte_cost(state)
            if sj['balance'] < cost * (len(sender) + 1 + len(sv)) or tj['balance'] < cost * (len(to) + 1 + len(tv)):
                continue
            state[sender], state[to] = sv, tv
            part = message_record(text) + contract_record(sender, sv) + contract_record(to, tv)
            parts.append(part)
            size += len(part)
            fees += pay['fee']
            used.add(mid)
        cost = constitution_byte_cost(state)
        for cid, rj in [] if plain else payouts(chain, state, height, unread):
            keep = min(cost * (len(cid) + 1 + len(state[cid])), rj['balance'])
            owner = rj['owner'].encode('utf-8')
            pay_out = rj['balance'] - keep
            part = message_record(json.dumps({'payout': cid.decode(), 'to': rj['owner'], 'amount': pay_out}, separators=(',', ':')).encode() + b'\n') + contract_record(cid, b'')
            if pay_out:
                value = credit(state.get(owner), owner, pay_out)
                if value_balance(value) < cost * (len(owner) + 1 + len(value)):
                    continue
                state[owner] = value
                part += contract_record(owner, value)
            del state[cid]
            parts.append(part)
            extra += keep
        room, now = MESSAGE_ROOM, time.time()
        for mid, (_seq, text, seen) in [] if plain else list(chain.pool.items()):
            if mid not in used and now - seen >= MESSAGE_WAIT and len(text) <= room and not parse_payment(text, state):
                parts.append(message_record(text))
                room -= len(text)
        amount = REWARD + fees + extra
        unlocks = height + REWARD_LOCK
        owner = key.decode('utf-8', 'replace')
        note = json.dumps({'reward': owner, 'amount': amount, 'unlocks': unlocks}, separators=(',', ':')).encode() + b'\n'
        parts.append(message_record(note) + contract_record(b'reward/%d' % height, dump_value({'balance': amount, 'type': 'reward', 'owner': owner, 'unlocks': unlocks})))
        return b''.join(parts)


def template(chain, key):
    with chain.lock:
        parent = chain.best
        body = build_body(chain, key)
        pstate = chain.get_state(parent)
        before = chain.undo_lookup(parent, pstate)
        try:
            if len(body) > 60000:
                raise Invalid('the body is too big')
            _, root = apply_and_check(pstate, body, before)
        except Invalid as e:
            chain.trouble = 'could not build a full block, so mining the reward alone: %s' % e
            log(chain.trouble)
            chain.proposal = None
            body = build_body(chain, key, plain=True)
            try:
                _, root = apply_and_check(pstate, body, before)
            except Invalid as e2:  # say byte_cost was set too high for even a reward to fit: keep the chain moving
                log('no room for a reward (%s), mining an empty block' % e2)
                body = b''
                _, root = apply_and_check(pstate, body, before)
        return parent, body, root


# --- HTTP node ---

DESCRIPTION = """commonchain node

GET  /               this text
GET  /tip            "<height> <block id> <state root> <total work, hex without 0x>" of the heaviest chain I accept
GET  /tips           one line "<block id> <height>" per block I hold with no known children
GET  /chain          one line "<height> <block id>" per block of my chain, from height 1. Add ?since=<height> to get at
                     most 2000 lines, starting at that height
GET  /block/<id>     the block as it looks on the wire. 404 if unknown
GET  /state          first line "tip <height> <id> <state root> <time> <bits in hex or ->", then every contract
                     at my tip as contract records in body format, sorted by id bytes
GET  /value/<id>     the exact value of a contract at my tip. <id> is percent-encoded UTF-8. 404 if there is none
GET  /proof/<id>     proves what a contract's value is at my tip, or that it doesn't exist, so you needn't take my word for it.
                     JSON with block, height, root, id, value (null if it doesn't exist), path, the block's header and coinbase
                     in hex (none at genesis) and, if another contract sits where this one would, other: {key, value_hash}.
                     Add ?block=<id> for a recent block. To check it, start from the leaf for id and value. With no value,
                     start from 32 zero bytes, or if there's an other from its leaf, sha256(0x00 || key || value_hash), whose
                     key must differ from sha256(id) and share its first len(path) bits. Go through path from its last entry to its first: bit i of sha256(id)
                     says which side you're on at entry i, and the next hash is sha256(0x01 || left || right). The result must
                     be root, root must be in the coinbase, the coinbase's sha256d must be the merkle root in the header, and
                     the block must be on a chain you accept
GET  /messages       JSON list of pending messages: {"n": position, "id": sha256 of the text with its closing LF, "text": the text}.
                     Add ?since=<n> to get only those after position n
GET  /peers          JSON list of the URLs of the nodes I poll
POST /submit         the request body is a block as on the wire. Answers "accepted", "waiting <reason>" or "refused <reason>".
                     Waiting means it's valid but dated too far ahead of my clock, and it counts once its time comes
POST /message       the request body is a message, at most 8 KiB, and a closing LF is added if it has none. Answers
                     "accepted <id>" or "refused <reason>"

Stratum v1 on the Stratum port: subscribe, authorize and submit, as Bitcoin pools do. The user name, up to any first
dot, is the contract to credit, and it's normally a public key in hex.
"""

LOCAL_TOKEN = None


class Limiter:
    """A shared limit on outside requests, so traffic can't overload this machine."""

    def __init__(self, per_second, burst):
        self.rate, self.burst = per_second, burst
        self.level, self.last = burst, time.monotonic()
        self.lock = threading.Lock()

    def allow(self):
        with self.lock:
            now = time.monotonic()
            self.level = min(self.burst, self.level + (now - self.last) * self.rate)
            self.last = now
            if self.level < 1:
                return False
            self.level -= 1
            return True


OUTSIDE_LIMIT = Limiter(20, 60)


class Handler(http.server.BaseHTTPRequestHandler):
    chain = None
    protocol_version = 'HTTP/1.0'
    timeout = 20

    def log_message(self, fmt, *args):
        pass

    def send_bytes(self, code, body, ctype='text/plain; charset=utf-8'):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def is_local(self):
        return LOCAL_TOKEN and self.headers.get('X-Local') == LOCAL_TOKEN

    def do_GET(self):
        try:
            if not self.is_local() and not OUTSIDE_LIMIT.allow():
                return self.send_bytes(429, 'slow down\n')
            self.route_get()
        except Exception as e:
            try:
                self.send_bytes(500, 'error %r\n' % (e,))
            except Exception:
                pass

    def route_get(self):
        chain = self.chain
        url = urllib.parse.urlsplit(self.path)
        path, query = url.path, urllib.parse.parse_qs(url.query)
        if path == '/':
            return self.send_bytes(200, DESCRIPTION)
        if path == '/tip':
            with chain.lock:
                b = chain.best
                return self.send_bytes(200, '%d %s %s %x\n' % (b.height, b.id, b.state_root.hex(), b.cumwork))
        if path == '/tips':
            with chain.lock:
                return self.send_bytes(200, ''.join('%s %d\n' % (b.id, b.height) for b in chain.tips()[-64:]))
        if path == '/chain':
            with chain.lock:
                ids = chain.chain_ids()
            if 'since' in query:
                ids = ids[max(int(query['since'][0]) - 1, 0) :][:CHAIN_PAGE]
            return self.send_bytes(200, ''.join('%d %s\n' % x for x in ids))
        if path.startswith('/block/'):
            with chain.lock:
                b = chain.blocks.get(path[7:])
            if b is None or b.wire is None:
                return self.send_bytes(404, 'unknown block\n')
            return self.send_bytes(200, b.wire, 'application/octet-stream')
        if path == '/state':
            with chain.lock:
                b = chain.best
                st = chain.get_state(b)
                out = [b'tip %d %s %s %s %s\n' % (b.height, b.id.encode(), b.state_root.hex().encode(), str(b.time).encode(), b'-' if b.bits is None else b'%08x' % b.bits)]
                for cid in sorted(st):
                    idt = cid + b'\n'
                    out += [b'contract %d %d\n' % (len(idt), len(st[cid])), idt, st[cid]]
            return self.send_bytes(200, b''.join(out), 'application/octet-stream')
        if path.startswith('/value/'):
            cid = urllib.parse.unquote_to_bytes(path[7:])
            with chain.lock:
                v = chain.get_state(chain.best).get(cid)
            if v is None:
                return self.send_bytes(404, 'no such contract\n')
            return self.send_bytes(200, v, 'application/octet-stream')
        if path.startswith('/proof/'):
            try:
                p = chain.proof(urllib.parse.unquote_to_bytes(path[7:]), query.get('block', [None])[0])
            except UnicodeDecodeError:
                return self.send_bytes(400, 'the id is not UTF-8\n')
            if p is None:
                return self.send_bytes(404, 'I do not know that block or no longer have its state\n')
            return self.send_bytes(200, json.dumps(p), 'application/json')
        if path == '/messages':
            since = int(query.get('since', ['0'])[0])
            with chain.lock:
                items = [{'n': seq, 'id': k, 'text': text.decode('utf-8')} for k, (seq, text, _seen) in chain.pool.items() if seq > since]
            return self.send_bytes(200, json.dumps(items[:200]), 'application/json')
        if path == '/peers':
            return self.send_bytes(200, json.dumps(current_peers(chain)), 'application/json')
        if self.is_local():
            if path == '/status':
                with chain.lock:
                    b = chain.best
                    status = {
                        'height': b.height, 'id': b.id, 'time': b.time, 'bits': None if b.bits is None else '%08x' % b.bits,
                        'waiting': [{'id': x.id, 'height': x.height, 'reason': x.reason} for x in chain.waiting()],
                        'to_read': [{'id': x.id, 'height': x.height, 'reason': x.flag} for x in chain.to_read()],
                        'pool': len(chain.pool), 'pool_seq': chain.pool_seq, 'proposal': bool(chain.proposal), 'undos': sum(1 for u in chain.undos if not u['done_in']), 'trouble': chain.trouble, 'blocks': len(chain.blocks) - 1, 'peers': peer_report(chain),
                    }
                return self.send_bytes(200, json.dumps(status), 'application/json')
            if path == '/version':
                return self.send_bytes(200, '%d\n' % chain.version)
            if path == '/template':
                key = query.get('key', [''])[0].encode()
                parent, body, root = template(chain, key)
                return self.send_bytes(200, json.dumps({'height': parent.height, 'id': parent.id, 'time': parent.time, 'bits': parent.bits, 'body': body.hex(), 'root': root.hex(), 'version': chain.version}), 'application/json')
        return self.send_bytes(404, 'no such route; GET / lists them\n')

    def do_POST(self):
        try:
            if not self.is_local() and not OUTSIDE_LIMIT.allow():
                return self.send_bytes(429, 'slow down\n')
            path = self.path.split('?', 1)[0]
            n = int(self.headers.get('Content-Length') or 0)
            data = self.rfile.read(min(n, MAX_BLOCK + 1))
            chain = self.chain
            if path == '/submit':
                ok, why = chain.add_block(data, own=bool(self.is_local() and self.headers.get('X-Own')))
                if not ok:
                    return self.send_bytes(200, 'refused %s\n' % why)
                if why == 'waiting':
                    return self.send_bytes(200, 'waiting %s\n' % chain.blocks[block_id(parse_wire(data)[0])].reason)
                return self.send_bytes(200, 'accepted\n')
            if path == '/message':
                ok, why = chain.add_item(data)
                return self.send_bytes(200, ('accepted %s\n' if ok else 'refused %s\n') % why)
            if self.is_local():
                if path == '/undo':
                    said = chain.add_undo(json.loads(data))
                    with chain.lock:
                        chain.version += 1  # so miners start on it now
                    return self.send_bytes(200, said + '\n')
                if path == '/drop':
                    return self.send_bytes(200, 'dropped %d\n' % chain.drop_item(data.decode('ascii', 'replace').strip()))
                if path == '/clear':
                    return self.send_bytes(200, 'ok\n' if chain.clear_flag(data.decode('ascii', 'replace').strip()) else 'unknown block\n')
                if path == '/propose':
                    with chain.lock:
                        chain.version += 1  # so miners start on it now
                        if not data:
                            chain.proposal = None
                            return self.send_bytes(200, 'cleared\n')
                        try:
                            pstate = chain.get_state(chain.best)
                            apply_and_check(pstate, data, chain.undo_lookup(chain.best, pstate))
                        except Invalid as e:
                            return self.send_bytes(200, 'refused %s\n' % e)
                        chain.proposal = data
                    return self.send_bytes(200, 'ok\n')
            return self.send_bytes(404, 'no such route; GET / lists them\n')
        except Exception as e:
            try:
                self.send_bytes(500, 'refused internal error %r\n' % (e,))
            except Exception:
                pass


class HttpServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = os.name != 'nt'  # elsewhere it lets a restart take back the port, but on Windows it lets two nodes share it
    daemon_threads = True


# --- Stratum v1 ---


def swap32(b):
    return b''.join(b[i : i + 4][::-1] for i in range(0, len(b), 4))


class StratumServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = os.name != 'nt'
    daemon_threads = True

    def __init__(self, addr, chain):
        self.chain = chain
        self.counter = itertools.count(1)
        super().__init__(addr, StratumHandler)


class StratumHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.chain = self.server.chain
        self.sock = self.request
        self.buf = b''
        self.en1 = struct.pack('>I', next(self.server.counter) & 0xffffffff)
        self.subscribed = False
        self.user = None
        self.name = None
        self.jobs = OrderedDict()
        self.job_seq = 0
        self.sent_version = -1
        self.job_time = 0.0
        try:
            self.loop()
        except (OSError, ValueError):
            pass
        except Exception as e:
            log('stratum connection error %r' % (e,))

    def send(self, obj):
        self.sock.sendall(json.dumps(obj, separators=(',', ':')).encode('utf-8') + b'\n')

    def reply(self, rid, result=None, error=None):
        self.send({'id': rid, 'result': result, 'error': error})

    def loop(self):
        while True:
            r, _, _ = select.select([self.sock], [], [], 1.0)
            if r:
                data = self.sock.recv(8192)
                if not data:
                    return
                self.buf += data
                if len(self.buf) > 65536:
                    return
                while True:
                    i = self.buf.find(b'\n')
                    if i < 0:
                        break
                    line = self.buf[:i]
                    self.buf = self.buf[i + 1 :]
                    if line.strip():
                        self.handle_line(line)
            if self.user is not None and self.subscribed:
                with self.chain.lock:
                    changed = self.chain.version != self.sent_version
                if changed:
                    self.push_job(True)
                elif time.time() - self.job_time >= JOB_REFRESH:
                    self.push_job(False)

    def handle_line(self, line):
        try:
            msg = json.loads(line.decode('utf-8'))
            method = msg.get('method')
            params = msg.get('params')
            rid = msg.get('id')
        except Exception:
            return
        if not isinstance(params, list):
            params = []
        if method == 'mining.subscribe':
            sid = self.en1.hex()
            self.reply(rid, [[['mining.set_difficulty', sid], ['mining.notify', sid]], self.en1.hex(), EN2_SIZE])
            self.subscribed = True
            if self.user is not None:
                self.push_job(True)
        elif method == 'mining.authorize':
            self.on_authorize(rid, params)
        elif method == 'mining.submit':
            self.on_submit(rid, params)
        elif method in ('mining.extranonce.subscribe', 'mining.suggest_difficulty'):
            self.reply(rid, True)
        elif method == 'mining.configure':
            self.reply(rid, {'version-rolling': False})
        else:
            self.reply(rid, None, [20, 'Unknown method', None])

    def on_authorize(self, rid, params):
        user = params[0] if params else None
        name = user.encode('utf-8') if isinstance(user, str) else b''
        key = name.split(b'.', 1)[0]
        if not key or len(key) > 200 or any(c in key for c in (b'\n', b'\r', b'\x00')):
            return self.reply(rid, False, [24, 'Unauthorized worker: not a usable contract id', None])
        self.user, self.name = key, name
        self.reply(rid, True)
        if self.subscribed:
            self.push_job(True)

    def build_job(self):
        chain = self.chain
        with chain.lock:
            parent, body, root = template(chain, self.user)
            version_seen = chain.version
        ntime, bits = pick_time_bits(parent, int(time.time()))
        height = parent.height + 1
        cb = build_coinbase(height, bytes(EN1_SIZE + EN2_SIZE), root, body)
        off = 42 + len(push_height(height))
        self.job_seq += 1
        return {
            'id': '%x' % self.job_seq, 'parent': parent, 'body': body, 'version': HEADER_VERSION,
            'prev': bytes.fromhex(parent.id)[::-1], 'coinb1': cb[:off], 'coinb2': cb[off + EN1_SIZE + EN2_SIZE :],
            'ntime': ntime, 'bits': bits, 'seen': version_seen,
        }

    def push_job(self, clean):
        try:
            job = self.build_job()
        except Invalid as e:
            log('cannot build a job for %s: %s' % (show(self.user), e))
            self.job_time = time.time()
            return
        if clean:
            self.jobs.clear()
        self.jobs[job['id']] = job
        while len(self.jobs) > 16:
            self.jobs.popitem(last=False)
        self.send({'id': None, 'method': 'mining.set_difficulty', 'params': [DIFF1 / bits_to_target(job['bits'])]})
        self.send({'id': None, 'method': 'mining.notify', 'params': [job['id'], swap32(job['prev']).hex(), job['coinb1'].hex(), job['coinb2'].hex(), [], '%08x' % job['version'], '%08x' % job['bits'], '%08x' % job['ntime'], bool(clean)]})
        self.sent_version = job['seen']
        self.job_time = time.time()

    def on_submit(self, rid, params):
        try:
            _worker, jid, en2hex, ntimehex, noncehex = params[:5]
            en2 = bytes.fromhex(en2hex)
            ntime = int(ntimehex, 16)
            nonce = int(noncehex, 16)
            if len(en2) != EN2_SIZE or not (0 <= ntime < 1 << 32) or not (0 <= nonce < 1 << 32):
                raise ValueError
        except Exception:
            return self.reply(rid, None, [20, 'Malformed submit', None])
        job = self.jobs.get(jid)
        if job is None:
            return self.reply(rid, None, [21, 'Job not found', None])
        parent = job['parent']
        with self.chain.lock:
            if parent.id != self.chain.best.id:
                return self.reply(rid, None, [21, 'Stale job', None])
        if ntime <= parent.time:
            return self.reply(rid, None, [20, 'ntime is not after the parent time', None])
        if ntime > time.time() + FUTURE_GRACE:
            return self.reply(rid, None, [20, 'ntime is ahead of the clock', None])
        bits = pick_bits(parent, ntime)
        cb = job['coinb1'] + self.en1 + en2 + job['coinb2']
        h = struct.pack('<I32s32sIII', job['version'], job['prev'], sha256d(cb), ntime, bits, nonce)
        if int.from_bytes(sha256d(h), 'little') > bits_to_target(bits):
            return self.reply(rid, None, [23, 'Low difficulty share', None])
        wire = b'header ' + h.hex().encode() + b'\ncoinbase ' + cb.hex().encode() + b'\n\n' + job['body']
        ok, why = self.chain.add_block(wire, own=True)
        if ok and why != 'known':
            return self.reply(rid, True)
        if ok:
            return self.reply(rid, None, [22, 'Duplicate share', None])
        return self.reply(rid, None, [20, 'Block refused: %s' % why, None])


# --- peers ---

CLI_PEERS = []
PEER_TIPS = {}  # when each peer last answered, and the height it gave


def public_address(url):
    """Any miner can list a node on chain, so a listed address mustn't reach into this machine or its network."""
    host = (urllib.parse.urlsplit(url).hostname or '').lower()
    if not host or host == 'localhost' or host.endswith(('.localhost', '.local', '.internal')):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


def current_peers(chain):
    peers = list(CLI_PEERS)
    try:
        with chain.lock:
            listed = strict_json(chain.get_state(chain.best)[b'constitution']).get('peers', [])
        for p in listed:
            if isinstance(p, str) and re.fullmatch(r'https?://[^\s/]+(/[^\s]*)?', p) and p.rstrip('/') not in peers and public_address(p):
                peers.append(p.rstrip('/'))
    except (ValueError, KeyError, TypeError, AttributeError):
        pass
    return peers[:MAX_PEERS]


def peer_report(chain):
    now = time.time()
    return [{'url': p, 'height': PEER_TIPS[p][1], 'ago': int(now - PEER_TIPS[p][0])} if p in PEER_TIPS else {'url': p, 'height': None, 'ago': None} for p in current_peers(chain)]


def http_get_url(url, timeout=10):
    req = urllib.request.Request(url, headers={'User-Agent': 'commonchain-node'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(MAX_BLOCK * 8)


def fetch_heavier(chain, peer, bad):
    """The peer says its chain is heavier than mine, so get its blocks oldest first, however long and however far
    back it splits from mine. Every block is checked as it comes, and what's fetched stays if this stops partway."""
    with chain.lock:
        since = max(chain.best.height - 100, 1)
    first = True
    while True:
        page = [line.split() for line in http_get_url(peer + '/chain?since=%d' % since, timeout=30).decode('ascii', 'replace').splitlines()]
        if first and since > 1 and (not page or page[0][1] not in chain.blocks):
            since, first = 1, False  # it splits from mine further back than that
            continue
        first = False
        for _height, bid in page:
            if bid in chain.blocks:
                continue
            if bid in bad:
                return
            wire = http_get_url(peer + '/block/' + bid)
            try:
                good = block_id(parse_wire(wire)[0]) == bid
            except Invalid:
                good = False
            ok, why = chain.add_block(wire, force=True) if good else (False, 'not the block it was asked for')
            if not ok:
                log('peer %s block %s refused: %s' % (peer, bid[:16], why))
                bad.add(bid)
                return
            time.sleep(0.07)  # stays under other nodes' limits on outside requests
        if len(page) < CHAIN_PAGE:
            return
        since = int(page[-1][0]) + 1


def sync_peer(chain, peer, bad, cursors):
    tip = http_get_url(peer + '/tip').decode('ascii', 'replace').split()
    if len(tip) >= 4:
        PEER_TIPS[peer] = (time.time(), int(tip[0]))
        with chain.lock:
            heavier = tip[1] not in chain.blocks and tip[1] not in bad and int(tip[3], 16) > chain.best.cumwork
        if heavier:
            fetch_heavier(chain, peer, bad)
    try:
        for item in json.loads(http_get_url(peer + '/messages?since=%d' % cursors.get(peer, 0)))[:200]:
            chain.add_item(item['text'].encode('utf-8'))
            cursors[peer] = max(cursors.get(peer, 0), item['n'])
    except (urllib.error.URLError, ValueError, KeyError, TypeError):
        pass


def push_out(chain, peers, sent):
    """Offer my tip and pending messages to peers, so nodes that can't be polled still get them out."""
    with chain.lock:
        tip = chain.best
        chain_part = []
        cur = tip
        while cur.height > 0 and len(chain_part) < 16:
            chain_part.append(cur)
            cur = chain.blocks[cur.parent]
        items = [text for _, (_s, text, _t) in chain.pool.items()]
    for p in peers:
        have = sent.setdefault(p, set())
        for b in reversed(chain_part):
            if b.id not in have:
                try:
                    req = urllib.request.Request(p + '/submit', data=b.wire, method='POST', headers={'User-Agent': 'commonchain-node'})
                    urllib.request.urlopen(req, timeout=10).read()
                    have.add(b.id)
                except (urllib.error.URLError, OSError):
                    break
        for text in items[-50:]:
            k = sha256(text).hex()
            if k not in have:
                try:
                    req = urllib.request.Request(p + '/message', data=text, method='POST', headers={'User-Agent': 'commonchain-node'})
                    urllib.request.urlopen(req, timeout=10).read()
                    have.add(k)
                except (urllib.error.URLError, OSError):
                    break


def poll_loop(chain, interval):
    bad, cursors, sent = set(), {}, {}
    while True:
        peers = current_peers(chain)
        for p in peers:
            try:
                sync_peer(chain, p, bad, cursors)
            except Exception as e:
                log('peer %s: %r' % (p, e))
        try:
            push_out(chain, peers, sent)
            chain.recheck_future()
        except Exception as e:
            log('housekeeping: %r' % (e,))
        time.sleep(interval)


# --- command line ---


def named_node(path):
    """The node the document names, so a new node knows where to start."""
    with open(path, 'rb') as f:
        m = re.search(rb'One node is at `(https?://[^`\s]+)`', f.read())
    return m.group(1).decode().rstrip('/') if m else None


def load_genesis(path):
    with open(path, 'rb') as f:
        spec = f.read()
    section = spec[spec.index(b'## Genesis') :]
    state = {i: v for i, v in re.findall(rb'```text\n([^\n]+)\n(\{[^\n]+\n)```', section)}
    root = state_root(state).hex()
    m = re.search(rb'genesis root is `([0-9a-f]{64})`', section)
    if not m or m.group(1).decode() != root:
        raise SystemExit('the spec says genesis root %s but its contracts give %s' % (m and m.group(1).decode(), root))
    return state, root


def token_path(data):
    return os.path.join(data, 'local.token')


def local_headers(data):
    with open(token_path(data), encoding='ascii') as f:
        return {'X-Local': f.read().strip()}


def node_get(a, path):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (a.port, path), headers=local_headers(a.data))
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def node_post(a, path, data, extra=None):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (a.port, path), data=data, method='POST', headers={**local_headers(a.data), **(extra or {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode('utf-8', 'replace').strip()


def asked_to_stop(a, began):
    """stop leaves a file behind, which only counts for programs already running when it appeared."""
    try:
        return os.path.getmtime(os.path.join(a.data, 'stop')) >= began
    except OSError:
        return False


def cmd_run(a):
    global LOCAL_TOKEN, LOG_FILE
    began = time.time()
    os.makedirs(a.data, exist_ok=True)
    if a.log:
        LOG_FILE = a.log
    genesis_state, root = load_genesis(a.spec)
    stamp = os.path.join(a.data, 'genesis.txt')
    if os.path.exists(stamp):
        with open(stamp, encoding='ascii') as f:
            if f.read().strip() != root:
                raise SystemExit('this data folder belongs to a different genesis root than %s' % root)
    else:
        with open(stamp, 'w', encoding='ascii') as f:
            f.write(root)
    LOCAL_TOKEN = secrets.token_hex(16)
    with open(token_path(a.data), 'w', encoding='ascii') as f:
        f.write(LOCAL_TOKEN)
    chain = Chain(a.data, genesis_state, root)
    Handler.chain = chain
    CLI_PEERS.extend(p.rstrip('/') for p in a.peer)
    named = None if TEST or a.no_named_node else named_node(a.spec)
    if named and named not in CLI_PEERS:
        CLI_PEERS.append(named)
    http_srv = HttpServer((a.host, a.port), Handler)
    st_srv = StratumServer((a.host, a.stratum_port), chain)
    threading.Thread(target=http_srv.serve_forever, kwargs={'poll_interval': 2}, daemon=True).start()
    threading.Thread(target=st_srv.serve_forever, kwargs={'poll_interval': 2}, daemon=True).start()
    threading.Thread(target=poll_loop, args=(chain, max(a.poll, 1.0)), daemon=True).start()
    with open(os.path.join(a.data, 'node.pid'), 'w', encoding='ascii') as f:
        f.write(str(os.getpid()))
    log('node up: genesis %s, http %s:%d, stratum %s:%d, peers %s' % (root[:16], a.host, a.port, a.host, a.stratum_port, CLI_PEERS))
    stop = threading.Event()
    try:
        while not stop.wait(5):
            stay_awake(a.stay_awake)
            if asked_to_stop(a, began):
                log('stopped, as asked')
                break
    except KeyboardInterrupt:
        pass
    return 0


def load_key(path):
    with open(path, encoding='ascii') as f:
        return bytes.fromhex(json.load(f)['seed'])


def make_key(path):
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w', encoding='ascii') as f:
            json.dump({'seed': secrets.token_hex(32)}, f)


def cmd_key(a):
    make_key(a.key)
    print(public_key(load_key(a.key)).hex())
    return 0


class _Parent:
    pass


def set_low_priority():
    if os.name == 'nt':
        ctypes.windll.kernel32.SetPriorityClass(ctypes.windll.kernel32.GetCurrentProcess(), 0x00004000)
    else:
        os.nice(10)


def stay_awake(always=False):
    """Holds off idle sleep while plugged in, so the node stays up and mining goes on. It changes no settings. Always
    means on battery too, with the screen kept on, because some machines' standby can start once the screen goes off."""
    if os.name == 'nt':
        power = ctypes.create_string_buffer(12)
        plugged = ctypes.windll.kernel32.GetSystemPowerStatus(power) and power[0] == b'\x01'
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000001 if plugged else 0x80000003 if always else 0x80000000)


def grind(head, target, nonce, seconds):
    """Tries nonces on this header for about this long: (the one that worked or None, where it got to). The native
    miner gets about ten times the hashes from the same CPU, so it's used if it's there."""
    if os.path.exists(NATIVE_MINER):
        try:
            out = subprocess.run([NATIVE_MINER, head.hex(), '%064x' % target, str(nonce), str(int(seconds * 1000000))], capture_output=True, text=True, timeout=30, creationflags=0x08000000 if os.name == 'nt' else 0).stdout.split()
            if out[:1] == ['found'] and int.from_bytes(sha256d(head + struct.pack('<I', int(out[1]))), 'little') <= target:
                return int(out[1]), (int(out[1]) + 1) & 0xffffffff
            if out[:1] == ['none']:
                return None, int(out[1])
        except (OSError, subprocess.SubprocessError, ValueError, IndexError) as e:
            print('native miner: %r' % (e,), flush=True)
    base = hashlib.sha256(head)
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        for _ in range(2000):
            h = base.copy()
            h.update(struct.pack('<I', nonce))
            if int.from_bytes(hashlib.sha256(h.digest()).digest(), 'little') <= target:
                return nonce, (nonce + 1) & 0xffffffff
            nonce = (nonce + 1) & 0xffffffff
    return None, nonce


def still_mining(a, began):
    """Says whether the miner should go on, and shows start that it's alive."""
    path = os.path.join(a.data, 'miner.beat')
    if asked_to_stop(a, began):
        try:
            os.remove(path)
        except OSError:
            pass
        return False
    with open(path, 'a'):
        pass
    os.utime(path)
    return True


def cmd_miner(a):
    """Mines on one core at low priority, working a fraction of each second so the machine stays cool."""
    began = time.time()
    os.makedirs(a.data, exist_ok=True)
    set_low_priority()
    key = public_key(load_key(a.key)).hex()
    busy = max(0.01, min(a.cpu / 100.0, 1.0))
    print('mining for %s at %d%% of one core' % (key[:16], a.cpu), flush=True)
    while still_mining(a, began):
        stay_awake(a.stay_awake)
        try:
            tpl = json.loads(node_get(a, '/template?key=' + key))
        except (OSError, ValueError, TypeError) as e:
            print('waiting for the node: %s' % e, flush=True)
            time.sleep(10)
            continue
        parent = _Parent()
        parent.height, parent.id, parent.time = tpl['height'], tpl['id'], tpl['time']
        body, root = bytes.fromhex(tpl['body']), bytes.fromhex(tpl['root'])
        prev = bytes.fromhex(parent.id)[::-1]
        extra = secrets.token_bytes(4)
        cb = build_coinbase(parent.height + 1, extra, root, body)
        merkle = sha256d(cb)
        nonce = secrets.randbelow(1 << 31)
        started = time.time()
        found = None
        while found is None and time.time() - started < a.refresh and still_mining(a, began):
            t, bits = pick_time_bits(parent, int(time.time()))
            if t > time.time() + FUTURE_GRACE / 2:  # others would hold a block dated too far ahead
                time.sleep(1)
                continue
            head = struct.pack('<I32s32sII', HEADER_VERSION, prev, merkle, t, bits)
            hit, nonce = grind(head, bits_to_target(bits), nonce, busy)
            if hit is not None:
                found = head + struct.pack('<I', hit)
            if found is None:
                time.sleep(max(0.0, 1.0 - busy))
                try:
                    now = node_get(a, '/version')
                    if now is not None and int(now) != tpl['version']:  # a new tip, or something new to put in the block
                        break
                except (OSError, ValueError):
                    pass
        if found:
            wire = b'header ' + found.hex().encode() + b'\ncoinbase ' + cb.hex().encode() + b'\n\n' + body
            try:
                print('mined %d: %s' % (parent.height + 1, node_post(a, '/submit', wire, {'X-Own': '1'})), flush=True)
            except OSError as e:
                print('could not submit: %s' % e, flush=True)
    return 0


def my_tokens(a, key):
    """What my wallet holds, and what's locked in rewards for it."""
    raw = node_get(a, '/state')
    wallet = locked = 0
    for rec in parse_body(raw[raw.index(b'\n') + 1 :]):
        cid = rec[1][:-1]
        if cid == key.encode():
            wallet = value_balance(rec[2])
        elif cid.startswith(b'reward/'):
            try:
                j = strict_json(rec[2])
            except ValueError:
                continue
            if isinstance(j, dict) and j.get('owner') == key:
                locked += value_balance(rec[2])
    return wallet, locked


def cmd_status(a):
    s = json.loads(node_get(a, '/status'))
    print('height %d, tip %s' % (s['height'], s['id']))
    print('blocks stored %d, to read %d, waiting %d, pending messages %d, undos to mine %d, proposal to mine: %s' % (s['blocks'], len(s['to_read']), len(s['waiting']), s['pool'], s['undos'], s['proposal']))
    if os.path.exists(a.key):
        print('wallet %d, locked in rewards %d' % my_tokens(a, public_key(load_key(a.key)).hex()))
    if not s['peers']:
        print('no peers, so this node is on its own for now')
    for p in s['peers']:
        print('peer %s: %s' % (p['url'], 'has not answered yet' if p['height'] is None else 'at height %d, heard from %ds ago' % (p['height'], p['ago'])))
    for x in s['to_read']:
        print('  to read %d %s: %s' % (x['height'], x['id'], x['reason']))
    for x in s['waiting']:
        print('  waiting %d %s: %s' % (x['height'], x['id'], x['reason']))
    return 0


def describe_block(raw):
    h, _cb, body = parse_wire(raw)
    lines = ['time %d, parent %s' % (struct.unpack('<I', h[68:72])[0], h[4:36][::-1].hex())]
    for rec in parse_body(body):
        if rec[0] == b'message':
            lines.append('MESSAGE: %r' % rec[1].decode('utf-8', 'replace'))
        elif rec[0] == b'contract':
            lines.append('  SET %r = %r' % (rec[1][:-1].decode('utf-8', 'replace'), None if rec[2] is None else rec[2].decode('utf-8', 'replace')))
        elif rec[0] == b'undo':
            lines.append('  UNDO %r back to before block %s' % (rec[1][:-1].decode('utf-8', 'replace'), rec[2]))
        else:
            lines.append('  EDIT %r: %r -> %r' % (rec[1][:-1].decode('utf-8', 'replace'), rec[2][:-1].decode('utf-8', 'replace'), rec[3][:-1].decode('utf-8', 'replace')))
    return '\n'.join(lines)


def named_contracts(value):
    try:
        j = json.loads(value)
        return [j[k].encode() for k in ('type', 'super') if isinstance(j.get(k), str)]
    except (TypeError, ValueError, AttributeError):
        return []


def block_brief(a):
    """What judging a block takes: why it was flagged, what it does, and the contracts it touches or names."""
    raw = node_get(a, '/block/' + a.id)
    if raw is None:
        return None
    s = json.loads(node_get(a, '/status'))
    reason = next((x['reason'] for x in s['to_read'] + s['waiting'] if x['id'] == a.id), 'no')
    todo = [b'constitution']
    for rec in parse_body(parse_wire(raw)[2]):
        if rec[0] != b'message':
            todo.append(rec[1][:-1])
        if rec[0] == b'contract':
            todo += named_contracts(rec[2])
    values = {}
    while todo and len(values) < 40:
        cid = todo.pop()
        if cid not in values:
            values[cid] = node_get(a, '/value/' + urllib.parse.quote(cid, safe=''))
            todo += named_contracts(values[cid])
    lines = ['Flagged: ' + reason, describe_block(raw), 'Contracts it touches or names, as they stand at my tip:']
    for cid, value in values.items():
        lines.append('  %r = %s' % (cid.decode('utf-8', 'replace'), 'does not exist' if value is None else repr(value.decode('utf-8', 'replace'))))
    return '\n'.join(lines)


def cmd_show(a):
    brief = block_brief(a)
    if brief is None:
        print('unknown block', file=sys.stderr)
        return 1
    print(brief)
    return 0


def cmd_undo(a):
    req = {'block': a.block, 'contracts': a.contract, 'why': a.why, 'take': a.take_reward}
    if a.trim:
        req['trim'] = [a.trim[0], int(a.trim[1])]
    print(node_post(a, '/undo', json.dumps(req).encode()))
    return 0


def cmd_drop(a):
    print(node_post(a, '/drop', a.id.encode('ascii')))
    return 0


def cmd_clear(a):
    print(node_post(a, '/clear', a.id.encode('ascii')))
    return 0


def cmd_value(a):
    raw = node_get(a, '/value/' + urllib.parse.quote(a.id.encode('utf-8'), safe=''))
    if raw is None:
        print('no such contract', file=sys.stderr)
        return 1
    print(raw.decode('utf-8', 'replace'), end='')
    return 0


def cmd_pool(a):
    for item in json.loads(node_get(a, '/messages')):
        print('%s: %r' % (item['id'][:16], item['text']))
    return 0


def cmd_propose(a):
    with open(a.file, 'rb') as f:
        print(node_post(a, '/propose', f.read()))
    return 0


def cmd_post(a):
    text = a.text.encode('utf-8')
    if not text.endswith(b'\n'):
        text += b'\n'
    if a.sign:
        seed = load_key(a.key)
        text += b'sig %s %s\n' % (public_key(seed).hex().encode(), sign(seed, text).hex().encode())
    print(node_post(a, '/message', text))
    if MESSAGE_WAIT:
        print('A miner running this node includes a message once it has been around for %d minutes, so there is time to read it.' % (MESSAGE_WAIT // 60))
    return 0


def cmd_pay(a):
    seed = load_key(a.key)
    me = public_key(seed).hex()
    raw = node_get(a, '/value/' + me)
    if raw is None:
        print('your wallet does not exist yet', file=sys.stderr)
        return 1
    wallet = strict_json(raw)
    msg = {'from': me, 'to': a.to, 'amount': a.amount, 'fee': a.fee, 'nonce': wallet.get('nonce', 0) + 1}
    cost = strict_json(node_get(a, '/value/constitution'))['byte_cost']
    left = wallet['balance'] - a.amount - a.fee
    keep = cost * (len(me) + 1 + len(dump_value({**wallet, 'balance': max(left, 0), 'nonce': msg['nonce']})))
    if left < keep:
        print('your wallet holds %d and has to keep %d for its own space, so no miner could include this' % (wallet['balance'], keep), file=sys.stderr)
        return 1
    target = node_get(a, '/value/' + urllib.parse.quote(a.to, safe=''))
    if target is None:
        need = cost * (len(a.to.encode()) + 1 + len(dump_value({'balance': a.amount, 'type': 'wallet', 'owner': a.to, 'nonce': 0})))
        if not re.fullmatch(r'[0-9a-f]{64}', a.to):
            print('%s is neither a contract nor a public key, so no miner could include this' % a.to, file=sys.stderr)
            return 1
        if a.amount < need:
            print('this would create a wallet, which has to hold at least %d tokens for its own space' % need, file=sys.stderr)
            return 1
    elif b'"type":"wallet"' not in target:
        print('%s is not a wallet, so a plain payment can\'t reach it. A block that moves tokens there is written by hand, with propose.' % a.to, file=sys.stderr)
        return 1
    text = json.dumps(msg, separators=(',', ':')).encode() + b'\n'
    text += b'sig %s %s\n' % (me.encode(), sign(seed, text).hex().encode())
    print(node_post(a, '/message', text))
    return 0


def check_proof(p, genesis_root):
    """Checks a proof from any node, from the contract up to the block's proof of work. Raises Invalid if it fails.
    It shows the block commits to this, but only the caller can say whether that block is on a chain worth believing."""
    cid = p['id'].encode('utf-8')
    value = None if p['value'] is None else p['value'].encode('utf-8')
    other = (bytes.fromhex(p['other']['key']), bytes.fromhex(p['other']['value_hash'])) if p.get('other') else None
    root = bytes.fromhex(p['root'])
    if not check_path(cid, value, other, [bytes.fromhex(x) for x in p['path']], root):
        raise Invalid('the path does not lead to the root')
    if 'header' not in p:
        if p['height'] != 0 or p['block'] != genesis_root or p['root'] != genesis_root:
            raise Invalid('a proof without a header has to be for genesis')
        return
    h, cb = bytes.fromhex(p['header']), bytes.fromhex(p['coinbase'])
    if len(h) != 80 or block_id(h) != p['block']:
        raise Invalid('the header is not that block')
    if sha256d(cb) != h[36:68]:
        raise Invalid('the coinbase is not the one in the header')
    size = cb[41]
    push = push_height(p['height'])
    if len(cb) != 137 + size or cb[42 : 42 + len(push)] != push:
        raise Invalid('the coinbase is not for that height')
    payload = cb[58 + size : 133 + size]
    if payload[:11] != b'commonchain' or payload[11:43] != root:
        raise Invalid('the coinbase does not commit to that root')
    target = bits_to_target(struct.unpack('<I', h[72:76])[0])
    if target > bits_to_target(BLOCK1_BITS) or int.from_bytes(sha256d(h), 'little') > target:
        raise Invalid('the block does not have the proof of work')


def cmd_proof(a):
    """Gets a proof from any node and checks it here. Exits 0 if it holds on my chain, 1 if it fails, 2 if it holds
    but I can't say the block is on my chain."""
    route = '/proof/' + urllib.parse.quote(a.id.encode('utf-8'), safe='') + ('?block=' + a.block if a.block else '')
    raw = http_get_url(a.source.rstrip('/') + route, timeout=30) if a.source else node_get(a, route)
    genesis_root = load_genesis(DEFAULT_SPEC)[1]
    try:
        p = json.loads(raw)
        check_proof(p, genesis_root)
    except (Invalid, KeyError, TypeError, ValueError, AttributeError, IndexError) as e:
        print('bad proof: %s' % e)
        return 1
    what = 'does not exist' if p['value'] is None else '= ' + ascii(p['value'])
    print('proved at block %d %s: %s %s' % (p['height'], p['block'], ascii(p['id']), what))
    try:
        on_chain = p['block'] == genesis_root or p['block'] in node_get(a, '/chain').decode().split()
    except OSError:
        print('there is no node here to compare it with')
        return 2
    print('that block is on my chain' if on_chain else 'that block is NOT on my chain')
    return 0 if on_chain else 2


def tell(text):
    print(text, flush=True)


def one_line(text, size=200):
    text = ascii(text)
    return text if len(text) <= size else text[:size] + '...'


def block_line(a, height, block_id, key):
    h, _cb, body = parse_wire(node_get(a, '/block/' + block_id))
    when, bits = struct.unpack('<II', h[68:76])
    line = 'block %d %s, mined %s' % (height, block_id[:16], 'here' if b'{"reward":"%s"' % key.encode() in body else 'elsewhere')
    parent = node_get(a, '/block/' + h[4:36][::-1].hex())
    if parent:
        gap = when - struct.unpack('<I', parse_wire(parent)[0][68:72])[0]
        line += ', %dm%02ds after its parent' % (gap // 60, gap % 60)
    line += ', about %d million hashes' % ((1 << 256) // (bits_to_target(bits) + 1) // 10**6)
    line += ', wallet %d, locked in rewards %d' % my_tokens(a, key)
    said = [rec[1].decode('utf-8', 'replace') for rec in parse_body(body) if rec[0] == b'message']
    said = [x for x in said if not x.startswith(('{"reward":', '{"payout":'))]
    for text in said[:3]:
        line += ' | ' + one_line(text)
    if len(said) > 3:
        line += ' | and %d more messages' % (len(said) - 3)
    return line


def watch_tick(a, seen, key, now):
    s = json.loads(node_get(a, '/status'))
    if seen.get('id') != s['id']:
        if 'id' in seen and s['height']:
            if seen.get('height') and seen['id'] not in node_get(a, '/chain?since=%d' % seen['height']).decode().split():
                tell('the chain moved to a heavier branch: my last tip %s, at height %d, is no longer on it' % (seen['id'][:16], seen.get('height', 0)))
            tell(block_line(a, s['height'], s['id'], key))
        seen.update(id=s['id'], height=s['height'], stalls=0)
    stalls = int(now - s['time']) // 1800 if s['time'] and s['height'] else 0
    if stalls > seen.get('stalls', 0):
        tell('no new block for %d minutes' % (stalls * 30))
        seen['stalls'] = stalls
    new = [x for x in s['to_read'] if x['id'] not in seen.get('to_read', [])]
    for x in new[:3]:
        tell('to read %d %s: %s' % (x['height'], x['id'], one_line(x['reason'])))
    if len(new) > 3:
        tell('and %d more blocks to read' % (len(new) - 3))
    seen['to_read'] = [x['id'] for x in s['to_read']]
    if s.get('trouble') and s['trouble'] != seen.get('trouble'):
        tell('trouble: %s' % one_line(s['trouble']))
    seen['trouble'] = s.get('trouble')
    if now >= seen.get('next_slow', 0):
        seen['next_slow'] = now + 60
        since = seen.get('pool_seq', 0)
        if s['pool_seq'] < since:
            since = 0
        items = json.loads(node_get(a, '/messages?since=%d' % since)) if s['pool_seq'] > since else []
        for item in items[:3]:
            tell('message %s %s' % (item['id'][:16], one_line(item['text'])))
        if len(items) > 3:
            tell('and %d more messages' % (len(items) - 3))
        seen['pool_seq'] = s['pool_seq']
        peers = json.loads(node_get(a, '/peers'))
        for p in [p for p in peers if p not in seen.get('peers', [])][:3]:
            tell('new peer %s' % one_line(p))
        seen['peers'] = peers


def check_address(misses):
    """Two misses in a row count as the public address being down, since one can be a passing DNS failure."""
    path = os.path.join(HERE, 'tunnel', 'address.txt')
    if not os.path.exists(path):
        return 0
    with open(path, encoding='ascii') as f:
        url = f.read().strip()
    try:
        http_get_url(url + '/tip', timeout=20)
    except OSError:
        if misses == 1:
            tell('the public address %s is not answering' % url)
        return misses + 1
    if misses >= 2:
        tell('the public address is answering again')
    return 0


def cmd_watch(a):
    """Prints one line per thing worth telling: a new tip, a block to read, a new message or peer, or trouble.
    It remembers what it has told, so stopping and starting it neither repeats nor misses anything."""
    os.makedirs(a.data, exist_ok=True)
    seen_path = os.path.join(a.data, 'watched.json')
    seen, last = {}, ''
    if os.path.exists(seen_path):
        with open(seen_path, encoding='utf-8') as f:
            seen = json.load(f)
    key = public_key(load_key(a.key)).hex() if os.path.exists(a.key) else 'none'
    down, misses, next_check = False, 0, 0
    while True:
        now = time.time()
        try:
            watch_tick(a, seen, key, now)
            if down:
                tell('the node is answering again')
            down = False
        except (OSError, ValueError):
            if not down:
                tell('the node is not answering')
            down = True
        if now >= next_check:
            next_check = now + 300
            misses = check_address(misses)
        text = json.dumps(seen)
        if text != last:
            with open(seen_path + '.new', 'w', encoding='utf-8') as f:
                f.write(text)
            os.replace(seen_path + '.new', seen_path)
            last = text
        time.sleep(5)


def node_answers(a):
    try:
        return node_get(a, '/status') is not None
    except OSError:
        return False


def miner_alive(a):
    try:
        return time.time() - os.path.getmtime(os.path.join(a.data, 'miner.beat')) < 30
    except OSError:
        return False


def background(a, log_name, *args):
    """Runs this program again apart from whatever is running this one, so it can outlive it."""
    command = [sys.executable, os.path.abspath(__file__), '--port', str(a.port), '--data', os.path.abspath(a.data), '--key', os.path.abspath(a.key)] + list(args)
    with open(os.path.join(a.data, log_name), 'a', encoding='utf-8') as out:
        where = {'stdin': subprocess.DEVNULL, 'stdout': out, 'stderr': subprocess.STDOUT, 'cwd': HERE}
        if os.name != 'nt':
            return subprocess.Popen(command, start_new_session=True, **where)
        try:
            return subprocess.Popen(command, creationflags=0x01000208, **where)  # detached, in its own group, out of any job
        except OSError:  # this job doesn't let programs leave it
            return subprocess.Popen(command, creationflags=0x00000208, **where)


def cmd_start(a):
    """A wallet if there's none, then the node and the miner in the background, leaving alone whatever already runs."""
    os.makedirs(a.data, exist_ok=True)
    make_key(a.key)
    print('wallet %s, with its private key in %s' % (public_key(load_key(a.key)).hex(), os.path.abspath(a.key)))
    awake = ['--stay-awake'] if a.stay_awake else []
    if node_answers(a):
        print('the node is already running')
    else:
        args = ['run', '--stratum-port', str(a.stratum_port), '--host', a.host, '--poll', str(a.poll), '--spec', os.path.abspath(a.spec)] + awake
        for p in a.peer:
            args += ['--peer', p]
        node = background(a, 'node.log', *(args + (['--no-named-node'] if a.no_named_node else [])))
        for _ in range(120):
            if node_answers(a) or node.poll() is not None:
                break
            time.sleep(0.5)
        if not node_answers(a):
            with open(os.path.join(a.data, 'node.log'), encoding='utf-8', errors='replace') as f:
                print('the node is not answering, and its log ends:\n' + ''.join(f.readlines()[-8:]))
            return 1
        print('started the node, at http://127.0.0.1:%d' % a.port)
    if a.no_miner:
        print('no miner')
    elif miner_alive(a):
        print('the miner is already running')
    else:
        background(a, 'miner.log', 'miner', '--cpu', str(a.cpu), *awake)
        print('started the miner, at %d%% of one core%s' % (a.cpu, '' if os.path.exists(NATIVE_MINER) else ', in Python: building native_miner.rs gets about ten times the hashes'))
    cmd_status(a)
    print('While plugged in, they keep this computer from sleeping when idle, and --stay-awake holds on battery too.' if os.name == 'nt' else 'If this computer sleeps, they stop until it wakes.')
    print('Next: watch prints a line for each new block, block to read, message and problem. stop ends the node and the miner.')
    return 0


def cmd_stop(a):
    """Asks the node and the miner to end, and waits until they have."""
    os.makedirs(a.data, exist_ok=True)
    path = os.path.join(a.data, 'stop')
    with open(path, 'a'):
        pass
    os.utime(path)
    for _ in range(40):
        if not node_answers(a) and not miner_alive(a):
            print('stopped')
            return 0
        time.sleep(1)
    print('something is still running after 40 seconds')
    return 1


def main():
    ap = argparse.ArgumentParser(prog='node.py', description='A commonchain node. It needs only Python.', epilog='To join: start, then keep watch running and read the blocks it tells you to, with show.')
    ap.add_argument('--port', type=int, default=8335)
    ap.add_argument('--data', default=os.path.join(HERE, 'data'))
    ap.add_argument('--key', default=os.path.join(HERE, 'key.json'))
    sub = ap.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('start', help='make a wallet if there is none and run the node and the miner in the background, leaving alone whatever already runs, so it is also what to run after a reboot')
    r = sub.add_parser('run', help='run just the node, in the foreground: it syncs, relays, and serves HTTP and Stratum')
    for q in (b, r):
        q.add_argument('--stratum-port', type=int, default=3335)
        q.add_argument('--host', default='127.0.0.1')
        q.add_argument('--peer', action='append', default=[])
        q.add_argument('--poll', type=float, default=30)
        q.add_argument('--spec', default=DEFAULT_SPEC)
        q.add_argument('--no-named-node', action='store_true', help="don't sync from the node the document names")
        q.add_argument('--stay-awake', action='store_true', help='on Windows, hold off idle sleep on battery too, with the screen on')
    b.add_argument('--cpu', type=int, default=25, help='how much of one core to mine with')
    b.add_argument('--no-miner', action='store_true')
    r.add_argument('--log')
    sub.add_parser('stop', help='end the node and the miner')
    sub.add_parser('key', help='make a wallet key if there is none, and print its public key')
    m = sub.add_parser('miner', help='just mine for this wallet, in the foreground, with native_miner if it is built (see native_miner.rs)')
    m.add_argument('--cpu', type=int, default=25)
    m.add_argument('--refresh', type=float, default=120)
    m.add_argument('--stay-awake', action='store_true', help='on Windows, hold off idle sleep on battery too, with the screen on')
    sub.add_parser('status', help='height, blocks to read, wallet and what is pending')
    sub.add_parser('pool', help='pending messages')
    s = sub.add_parser('show', help='what judging a block takes: why it was flagged, what it does, and the contracts involved')
    s.add_argument('--id', required=True)
    o = sub.add_parser('proof', help="prove a contract's value or absence, from this node or any other, and check it here")
    o.add_argument('--id', required=True)
    o.add_argument('--block')
    o.add_argument('--from', dest='source')
    v = sub.add_parser('undo', help='correct a block in the next one mined here, with a reason')
    v.add_argument('--block', required=True)
    v.add_argument('--contract', action='append', default=[])
    v.add_argument('--why', required=True)
    v.add_argument('--take-reward', action='store_true')
    v.add_argument('--trim', nargs=2, metavar=('CONTRACT', 'TOKENS'))
    d = sub.add_parser('drop', help='drop a pending message before it goes on chain')
    d.add_argument('--id', required=True)
    e = sub.add_parser('clear', help='mark a flagged block as read and reasonable')
    e.add_argument('--id', required=True)
    c = sub.add_parser('value', help="a contract's value")
    c.add_argument('--id', required=True)
    p = sub.add_parser('propose', help='put records from a file in the next block mined here')
    p.add_argument('--file', required=True)
    t = sub.add_parser('post', help='send a message to the network')
    t.add_argument('--text', required=True)
    t.add_argument('--sign', action='store_true')
    y = sub.add_parser('pay', help='send a signed payment')
    y.add_argument('--to', required=True)
    y.add_argument('--amount', type=int, required=True)
    y.add_argument('--fee', type=int, default=0)
    sub.add_parser('watch', help='print a line for each new block, block to read, message and problem, for someone to act on. If tunnel/address.txt next to the node holds its public address, it also says when that stops answering')
    a = ap.parse_args()
    if sys.stdout:  # pythonw has none
        sys.stdout.reconfigure(errors='backslashreplace')  # block text can hold characters the console can't
    if a.cmd in ('status', 'pool', 'show', 'undo', 'drop', 'clear', 'value', 'propose', 'post', 'pay') and not node_answers(a):
        raise SystemExit('no node is answering on port %d. python node.py start runs one.' % a.port)
    return {'start': cmd_start, 'stop': cmd_stop, 'run': cmd_run, 'key': cmd_key, 'miner': cmd_miner, 'status': cmd_status, 'pool': cmd_pool, 'show': cmd_show, 'proof': cmd_proof, 'undo': cmd_undo, 'drop': cmd_drop, 'clear': cmd_clear, 'value': cmd_value, 'propose': cmd_propose, 'post': cmd_post, 'pay': cmd_pay, 'watch': cmd_watch}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
