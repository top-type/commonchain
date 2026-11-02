# commonchain

A proof-of-work blockchain whose whole state is this document. A block is messages and the edits they should reasonably cause, and the chain with the most work is the real one.

Code checks only the work, the block size and that the edits apply. Everything else here, the tokens, these rules and what the chain is for included, is text that any block can change. Common sense decides what counts as reasonable, through what people and their AI agents choose to build on. AI agents reading every block, overseen by people where it matters, automate that common sense, which is what makes this possible. As in Nomic, changing the rules is a move.

Every document holds the whole state and how to make the next block, so anyone can carry on from any of them.

## Rules

These are exact, because every node has to agree on every hash. Something that breaks one isn't a block. They can change like the rest of this document, and a change takes hold once miners rebuild their nodes from the new text.

**Block.** A block is its records, an LF and its proof, and it can't be longer than 65536 bytes. Its records are any number of these, in any order:

```text
message <length>
<text>
edit <position> <find length> <replace length>
<find>
<replace>
```

Lengths are in bytes and don't count the LF after each text.

**Edits.** A block's document is its parent's document with the block's edits applied in order. Each edit replaces its find text, which has to be at its position in the document as the edits before it left it. Positions count bytes from 0, and an empty find text just inserts. A document can be any length.

**Proof.** A proof is ten lines, each ending in an LF:

```text
height <height>
start <time>
records <SHA-256 of the block's records>
document <SHA-256 of the block's document>
coinbase <hex>
version <8 hex digits>
parent <the parent's name>
time <time>
bits <8 hex digits>
nonce <number>
```

Hex is lowercase. Numbers, here and in records, are plain digits, at most 18 of them, with no leading zeros. Times are Unix seconds. `version` and `bits` are 32-bit numbers written in hex, and `time` and `nonce` fit in 32 bits.

**Work.** `coinbase` holds at most 200 bytes, which must contain the 32 bytes of the SHA-256 of the proof's first four lines with their LFs. Any form will do, and a Bitcoin coinbase transaction suits mining rigs best. A block's header is a Bitcoin block header, 80 bytes, built from `version`, `parent`, the merkle root, `time`, `bits` and `nonce`, stored the way Bitcoin stores them. The merkle root is the sha256d of the coinbase's bytes, and `sha256d` is SHA-256 twice. A block's name is the sha256d of its header, reversed the way Bitcoin displays it, which is also how `parent` is written. As a little-endian number, that sha256d must be at or below the target its bits decode to, and its bits must be the compact form of the target below, rounded down as Bitcoin does. So rigs mine only the header, and changing any byte changes the name.

**Target.** Blocks aim for one every 10 minutes, using ASERT (aserti3-2d, as on Bitcoin Cash) with a half-life of one hour, anchored at `start`, except that a block more than an hour after its parent also counts its own time. With `T` the target of bits `1e00ffff`, in Bitcoin's compact form:

```text
when = max(parent time, block time - 3600)
n = (when - start - 600 * parent height) * 65536
x = n / 3600, rounded toward zero
s = floor(x / 65536)
f = x - s * 65536
factor = 65536 + floor((195766423245049 * f + 971821376 * f^2 + 5127 * f^3 + 2^47) / 2^48)
target = floor(T * factor * 2^s / 65536)
```

The target never gets easier than `T` and is at least 1. Use arbitrary-precision integers. Everywhere else, a block's target means what its bits decode to, and its work is floor(2^256 / (target + 1)).

**Parents.** A block's height is one more than its parent's, its `start` is the same and its time is later. A block whose parent is 64 zeros starts a chain, with height 0, any `start`, target `T`, no edits and any document.

**Documents.** A document travels as its text, an LF and the proof of the block that gave it, and its SHA-256 has to match that proof. It goes by its block's name. This file is one, so its last ten lines are its proof. A copy with CRLF line endings has to be changed back to LF first.

**Following.** A node starts from a document it trusts, which it checks by all of this except what needs its parent. From there it follows the heaviest chain of valid blocks through that document, by total work, and of two equally heavy ones the one it saw first. It doesn't follow a block dated more than 10 minutes ahead of its clock until it no longer is. A copy that fails against its own proof says nothing about the name it carries, so the real one can still come.

**Network.** Nodes talk plain HTTP. Every node answers these routes, and describes what else it offers at `/`:

```text
GET  /tip                  <height> <name> of the block it follows
GET  /block/<name>         the block, or 404
POST /block                takes a block as its body, answering unknown parent if it needs older ones first
GET  /document/<name>      the document with its proof, or 404
GET  /messages?since=<n>   its pending messages after position n, with 0 for all, each a line <position> <length>, the text and an LF
POST /message              takes a message as its body
```

Nodes offer new blocks and messages to the peers they know and poll their tips, since not all of them can be reached. To catch up, walk back through parents from a peer's tip to a block you have. If that's too far, or they're gone, start over from a recent document.

**Check.** Code that follows these rules accepts this document and then this block on it, though they aren't meant for any chain. Each runs from the line after its opening fence to the line before its closing one. The document has the name `000000aaf7d121f0c2b02d73121f1fbc90e222751a310e7c84e2683855f58980`.

```text
some text
more text

height 0
start 1793539988
records e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
document 298f82988177061e5e5f1ae81b6ebe3e364c0e52d1b463847c690dc9656cb130
coinbase 01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0601003a4b4bd7ffffffff0100000000000000002d6a2b636f6d6d6f6e636861696e444fe7ceafcbd5f923e427133dbb3ae00ee538bcbbf5aff80d380ce1448a264300000000
version 20000000
parent 0000000000000000000000000000000000000000000000000000000000000000
time 1793539988
bits 1e00ffff
nonce 146345404
```

The block has the name `00000005754950ab2539314e6fa7f3bc97c3b7f1c46ac550fe10bd08fd3bd146`, and gives the document `other text`, an LF, `and a new line` and an LF.

```text
message 21
Every kind of record.
edit 0 9 10
some text
other text
edit 11 10 0
more text


edit 10 0 15


and a new line

height 1
start 1793539988
records 56f4d07022e9abdd0061247786f528734cd615a621d365ffdb2aa4b4b553cc08
document 404ca640bda821d924602ec13b5255160d91b3e2869c11cafd720f2b95819ea4
coinbase 01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff060101c7669a42ffffffff0100000000000000002d6a2b636f6d6d6f6e636861696e81d0d7c3fdcafaf6a1dc610e7284619ecb835dc2a6f15134a90af6f242bb26b900000000
version 20000000
parent 000000aaf7d121f0c2b02d73121f1fbc90e222751a310e7c84e2683855f58980
time 1793540588
bits 1e00ffff
nonce 846445321
```

With a parent at height 1000 and time `start` plus 500000, a block dated a minute after its parent has bits `1a12aa4d`, and one dated two hours after has bits `1a25549a`.

## Tokens

These are how things start, and they last as long as people hold to them.

A block's miner can credit itself the block's work plus any fees, saying so in a message `reward <wallet> <tokens>`, with `<tokens>` what lands in the wallet, so a new wallet's own line comes out of it. A token is an expected hash. A message's edits are the ones after it, up to the next message, and whoever sends it pays for the net bytes they add to this document, at floor(`byte cost` * `T` / target) tokens a byte, with the parent's `byte cost` and the block's target, and net bytes freed are refunded at that price. A new line counts whole, a number changing length doesn't, and message text is free. A later block can edit a bad block's reward back out, and it then goes to nobody.

byte cost 100000

A wallet is a line under Wallets, `<Ed25519 public key in hex> <tokens> <nonce>`, with nonce 0 when it's new. A payment is a message of two lines, `pay <from> <to> <amount> <fee> <the sender's nonce plus 1>` and `sig <public key> <signature>`, in hex and signing as in RFC 8032 the first line with its LF. A block that includes it moves the amount and gives the fee to its miner. A node is a line `peer <url>` under Peers.

So a block with a payment and a reward reads like this:

```text
message <length>
pay <a> <b> 500 10 4
sig <a> <signature>
edit <position> <find length> <replace length>
<a> 1510 3
<a> 1000 4
edit <position> <find length> <replace length>
<b> 200 7
<b> 700 7
message <length>
reward <m> 16777482
edit <position> <find length> <replace length>
<m> 90 12
<m> 16777572 12
```

## Wallets

## Peers

height 0
start 1793611902
records e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
document 2302c9804d7a71910ced02a3de725c86572f2dc5ddbe4c1f1968c3ea45d5b60d
coinbase 01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff060100fee99d93ffffffff0100000000000000002d6a2b636f6d6d6f6e636861696e5a5fba05b2362a37a091f075eddd8f7a767f0d849f8c8607b94e7cab0b0ff01d00000000
version 20000000
parent 0000000000000000000000000000000000000000000000000000000000000000
time 1793611902
bits 1e00ffff
nonce 488283653
