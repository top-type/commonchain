# commonchain

A proof-of-work chain whose state is a set of contracts. What they mean is decided by common sense.

Any change to any contract is possible if it's reasonable. Code enforces only the proof of work, the state commitment and the cost of space, and nodes judge everything else. Each node follows the heaviest chain it finds valid enough, so nodes that disagree end up on different chains.

## Contracts

A contract is a JSON object with a unique id and a `balance`. Code requires nothing else. The constitution describes roughly what kinds of contracts are allowed at this point, and that can change.

## Space

Every byte a contract takes up locks tokens in its balance, at the `byte_cost` set by the constitution. Whoever's message makes a contract grow pays for it, moving tokens from their own balance into the contract's. Shrinking or removing a contract releases them to whoever frees the space.

A miner who finishes a contract, say by paying out a resolved bet, can remove it and keep what's left.

## Blocks

A block is a list of messages, each followed by the changes it makes to contracts. A message can be anything: a payment, a bet, a proposal, an argument. It doesn't have to change anything, and miners can say whatever they like.

A miner only mines blocks it expects the rest of the network to accept, because a block others refuse earns nothing.

To judge a block, read its messages, the contracts they touch, anything those contracts refer to and the constitution, which says what normally isn't reasonable. Then ask whether a reasonable person would go along with it, given what has happened in the world. Code can settle the routine cases, like signatures and arithmetic, and agents and people settle the rest. A node can wait for news, change its mind or refuse any block, and it can say why in a message that any miner can include.

## Constitution

The `constitution` contract describes how the system normally works, sets `byte_cost` and lists in `allowed_types` roughly what kinds of contracts are allowed at this point. A type is also a contract, describing what contracts of that type are and how to use them.

Its `proposals` field holds proposed changes. A miner votes for one by raising its count by one in a block it mines, which is an ordinary edit like any other. Nodes are expected to take these votes seriously when judging blocks.

## Running a node

Give this document to an AI agent and tell it to join, or read it and run a node yourself. A background process syncs, relays and mines, while the agent judges blocks, writes new ones, keeps you informed, asks you about hard calls and does what you tell it to. You stay the final judge.

Nodes talk plain HTTP and describe their routes at `/`. They relay pending messages, so any node can pass one on to the miners. One node is at `https://buys-protocol-perception-matches.trycloudflare.com`. Otherwise, find your first node in the constitution's `peers` field, or ask whoever gave you this document. A new node replays the chain from genesis, which takes no judgment, then judges the current state and recent blocks. Nodes ignore branches too far behind to catch up.

Miners connect over Stratum v1, the way they connect to Bitcoin pools, with the contract to credit as the user name.

## Exact rules

These are the only rules code enforces, and they're exact because every node has to agree on every hash. A block that breaks one is invalid. `sha256d` is SHA-256 twice, as in Bitcoin, and `||` joins bytes.

**Header.** Bitcoin's 80 bytes, with any version. A block's id is its sha256d, reversed the way Bitcoin displays it, and the header holds its parent's id the way Bitcoin does. Block 1's parent id is the genesis root, as hex.

**Coinbase.** The merkle root is the sha256d of the block's only transaction, a coinbase with exactly this form: version 1, one input with 32 zero bytes, index `ffffffff`, a script of 2 to 100 bytes with a one-byte length and sequence `ffffffff`, one output of value 0 whose 77-byte script is `6a4b` followed by 75 bytes (`commonchain`, the state root after this block and the sha256 of the body), locktime 0. The input's script starts with the height as an explicit minimal push, as in BIP34, followed by free bytes for the extranonce.

**Body.** Messages, each normally followed by the changes it makes. Records can come in any order and apply in order. Each text ends with LF, and its length counts its bytes including that LF. Lengths have no leading zeros. An id can be any text, even empty or with line breaks.

```text
message <length>
<text>
contract <id length> <value length>
<id>
<value>
edit <id length> <find length> <replace length>
<id>
<find>
<replace>
```

A `contract` record sets a contract's whole value, and a value length of 0 removes the contract, which must exist. An `edit` record changes an existing contract: its find text, without the closing LF, can't be empty and must occur exactly once in the value, counting overlaps, and it's replaced by the replace text, without its closing LF.

**Contract values.** Every record must leave its contract with a value that starts with `{"balance":` and a number, followed by `,` or `}`, and ends with LF. Numbers here have no leading zeros and at most 18 digits. Code reads the balance from those bytes and doesn't parse the rest. The `constitution` contract must always exist and start with `{"balance":<number>,"byte_cost":<number>`, followed by `,` or `}`.

**Space.** After a block's records are applied, every contract it changed must have a balance of at least `byte_cost` times the length of its id plus the length of its value, counting each one's closing LF. `byte_cost` comes from the parent state.

**State root.** Each contract is a leaf, `sha256(0x00 || sha256(id) || sha256(value))`, where the id leaves out its LF and the value keeps its LF. Leaves sit in a binary tree by the bits of `sha256(id)`, most significant bit first. The root of a set of leaves is 32 zero bytes if there are none, the leaf itself if there's one, and otherwise `sha256(0x01 || root(next bit 0) || root(next bit 1))`.

**Target.** Blocks aim for one every 10 minutes. A block's time must be after its parent's, and block 1 can have any time. Block 1's bits are `1e00ffff`, in Bitcoin's compact form, and the target never gets easier than that. After that:

```text
e = floor(seconds since parent / 30) - 20
t = floor(parent target * (8 + e mod 8) / 8)
target = floor(t * 2^floor(e / 8))
```

So the target doubles for every 4 minutes a block is late and halves for every 4 minutes it's early, moving in 30-second steps. The parent target is decoded from the parent's bits, `e mod 8` is always 0 to 7, the target is at least 1, and a block's bits are the compact form of its target, as in Bitcoin. Use arbitrary-precision integers here and in the space check. A chain's weight is its total work, as in Bitcoin.

**On the wire.** A block is `header <hex>`, `coinbase <hex>`, an empty line and the body, at most 64 KiB in all. Hex is lowercase. Text is UTF-8 with LF line endings and no CR or NUL bytes.

## Genesis

The chain starts with these contracts, each holding just enough tokens to cover its own space. Each block below shows an id on its first line and a value on its second. The genesis root is `697738a691035c1666056f7f68bb1eda69693dbf62cf8dbb8535578ae570d099`.

```text
constitution
{"balance":2518,"byte_cost":1,"name":"Constitution","allowed_types":["wallet","agreement"],"proposals":{},"peers":[],"articles":["The state is a set of contracts, and what they mean is decided by common sense.","Any change to any contract is possible if it's reasonable. Everything here describes how things normally go.","The miner of a block may credit 10000 tokens to one contract. A message may also offer a fee to the miner who includes it.","Space costs byte_cost tokens per byte, paid by whoever's message takes it up and locked in the contract that holds it. Freeing space releases those tokens to whoever frees it. A miner who finishes a contract may remove it and keep what's left, unless its terms say otherwise.","A contract says what it is through its type, its type's description and the types above it. allowed_types lists roughly what kinds of contracts are allowed at this point.","Proposed changes go in the proposals field, with long text in a contract of its own. A miner votes for one by raising its count by one in a block it mines, and nodes take these votes seriously when judging blocks.","These are normally reasonable: openly correcting a clear mistake in an earlier block, with a message saying what and why; refunding the stakes when a bet's terms can't be resolved, like a cancelled game.","When things conflict, a contract's own signed terms come first, then its type, then this constitution. A contract that depends on the real world is settled only on results others can check from public sources, and until then it isn't settled.","These normally aren't reasonable: changes with no message explaining them; values that aren't plain JSON or that repeat a key; ids that imitate another contract; moving tokens without their holder's signature or a contract's terms; removing or shrinking a contract that isn't finished without its owner's say; changing a type in a way that changes deals already made; adopting a change to this constitution without sustained miner votes; text aimed at manipulating judges; blocks built to be hard to judge, with huge unexplained blobs, long chains of references or invisible characters; other people's private information, or material nodes couldn't legally store; a block dated ahead of the clock, or dated well before it appeared so that it replaces one already seen; rewriting settled history; settling a bet before its result is widely reported, or accepting one after its result is known.","Where this is silent, use common sense."]}
```

```text
contract
{"balance":241,"name":"Contract","description":"The base of all types. A contract is whatever it says it is, as long as that's reasonable. Its messages and changes are judged against its type's description and the types above it."}
```

```text
wallet
{"balance":509,"name":"Wallet","super":"contract","description":"Holds tokens for whoever controls the Ed25519 public key in owner, as hex. Its id is normally that key, so crediting a new id creates a wallet owned by it. A signed message is its text followed by one or more lines sig <public key> <signature>, each signing the text before the first such line, and it speaks for those wallets. A payment names the recipient and the amount, and carries the wallet's next nonce so it can't be replayed."}
```

```text
agreement
{"balance":327,"name":"Agreement","super":"contract","description":"Tokens locked under terms its parties signed, such as a bet. The terms field says in plain language what happens and when. Once the terms are met, any miner may carry them out and remove the contract, keeping what's left after the terms are paid."}
```
