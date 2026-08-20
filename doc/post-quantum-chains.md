# Lattica among the post-quantum chains

*Technical appendix. This document assumes familiarity with Bitcoin's consensus
rules and with post-quantum cryptography.*

A comparison is only worth reading if its claims can be checked, so the columns
here are sourced differently and the difference is marked.

The Lattica column comes from this repository at its initial commit, and each
figure links the file and line it is taken from. The other columns come from
those projects' own published material, cited at the end and dated — three of
the four are moving, and an undated table will be wrong within months.

A dash means *this document did not establish the figure from a cited source*.
It does not mean the project lacks the property. Filling those cells honestly
would mean reading each project's code, which is worth doing and is not what
this is.

## 1. The post-quantum chains

| | Bitcoin | QRL (mainnet) | QRL 2.0 "Zond" | Bitcoin Quantum | **Lattica** |
| --- | --- | --- | --- | --- | --- |
| Signature | ECDSA + Schnorr | XMSS | ML-DSA-87 | ML-DSA, beside ECDSA/Schnorr | **ML-DSA-44** |
| Family | elliptic curve | hash-based | lattice | lattice, beside a curve | **lattice** |
| Standard | — | RFC 8391, NIST SP 800-208 | FIPS 204 | FIPS 204 | **FIPS 204** |
| Signing state to keep | none | **one-time-signature index** | none | none | **none** |
| Public key | 33 B | — | 2592 B | — | **1313 B** |
| Signature | ~71 B | ~3 KB per tx | 4627 B | — | **2420 B** |
| Elliptic curve in repo | yes, by necessity | — | — | **yes** | **none** |
| Consensus | PoW | PoW | PoS | PoW | **PoW** |
| Smart contracts | script only | script only | EVM | script only | **script only** |
| Max supply | 21 M | 105 M | — | 21 M | **21 M** |
| Codebase | Bitcoin Core | own | own | Bitcoin Core repository fork | **Bitcoin Core architecture, own repository** |
| Status | live since 2009 | live since Jun 2018 | testnet v2, Q1 2026 | testnet v0.3.0, Mar 2026 | **mainnet, genesis 19 Aug 2026** |

Lattica's public key is 1313 rather than ML-DSA-44's 1312 because one leading
byte names the scheme, which is what lets a second scheme be added later without
a flag day ([`src/pubkey.h:62`](../src/pubkey.h#L62)).

Bitcoin Quantum's parameter set is left blank deliberately: its published
material describes *five* Dilithium opcodes, which suggests more than one
security level, and picking one to put in the table would be a guess.

Two of its cells were checked in the tree rather than taken from the project's
announcements, because a signature scheme is a claim about code. Dilithium is
implemented — [`src/crypto/dilithium/`](https://github.com/btq-ag/btq-core/tree/master/src/crypto)
holds the library alongside `dilithium_key`, `dilithium_pubkey`,
`dilithium_key_id` and `dilithium_wrapper`. And
[`src/secp256k1/`](https://github.com/btq-ag/btq-core/tree/master/src) is still
there beside it.

No ML-KEM or Kyber appears in either `src/` or `src/crypto/`, so the transport
looks unchanged from Bitcoin's. Post-quantum signatures without a post-quantum
handshake is a coherent position — the handshake protects a session, not a coin —
but it is a different scope from this chain's.

## 2. Lattica against Bitcoin, in detail

Every cell below is checkable — Bitcoin's from a decade of published consensus
rules, Lattica's from the linked line.

| | Bitcoin | **Lattica** |
| --- | --- | --- |
| Signature | ECDSA (~71 B) / Schnorr (64 B) | **ML-DSA-44 (2420 B)** |
| Public key | 33 B | **1313 B** |
| Secret key | 32 B | **2560 B** ([`key.h:57`](../src/key.h#L57)) |
| Chain hash (txid, Merkle) | SHA-256d | **SHA3-256** |
| Proof-of-work hash | SHA-256d | **SHA3-256d** ([`block.cpp:17`](../src/primitives/block.cpp#L17)) |
| P2P key agreement | ECDH over secp256k1 (BIP-324) | **ML-KEM-768** ([`v2cipher.h:18`](../src/v2cipher.h#L18)) |
| P2P packet cipher | FSChaCha20-Poly1305 | **FSChaCha20-Poly1305** |
| P2P length prefix | 3 bytes | **4 bytes** ([`v2cipher.h:47`](../src/v2cipher.h#L47)), so a 32 MB block is one packet |
| Block limit | 4,000,000 weight units | **32,000,000 bytes** ([`consensus.h:18`](../src/consensus/consensus.h#L18)) |
| Witness discount | 4× | **none** ([`consensus.h:31`](../src/consensus/consensus.h#L31)) |
| Sigops per block | 80,000 | **640,000** ([`consensus.h:25`](../src/consensus/consensus.h#L25)) — same one-per-50-bytes density |
| Ordinary payment (1-in, 2-out) | ~141 vB (~563 WU) | **3856 B** |
| Payments per block | ~7,100 | **~8,300** |
| Block interval | 10 min | **10 min** |
| Halving | 210,000 blocks | **210,000 blocks** |
| HD derivation | BIP-32, hardened + normal | **hardened only** ([`key.h:219`](../src/key.h#L219)) |
| Watch-only xpub | yes | **impossible** |

## 3. What actually separates them

Most rows above are detail. Three are not.

### The curve is still in every other tree

This is the row worth stopping on, and it is not an accusation — it follows from
what each project decided to be.

BIP-360 adds a post-quantum output type *alongside* the existing ones. A chain
implementing it must keep ECDSA and Schnorr working, because old outputs have to
stay spendable, so `libsecp256k1` stays vendored and every elliptic-curve address
keeps the exposure it always had. For Bitcoin itself this is unavoidable: there
are millions of coins behind published curve keys and no authority that can move
them. Any workable proposal there is additive, and additive means the curve
stays.

Bitcoin Quantum inherits that shape without inheriting the reason for it. It is
a new genesis that does not share Bitcoin's ledger, so it has no legacy UTXO set
to migrate — and the curve is in the repository anyway.

Lattica has no elliptic-curve implementation at all. Not disabled, not unused:
`git ls-files | grep -c secp256k1` returns zero. There is no EC output type to
pay to, and the operations a curve makes possible are absent by construction —
no `SignCompact` key recovery, no Schnorr key path, no `Neuter()`
([`key.h:182-201`](../src/key.h#L182-L201)). A chain with no curve cannot have a
curve-guarded coin.

The trade is real and not free. Lattica cannot import a Bitcoin balance and
cannot reuse the parts of Bitcoin's tooling that assume a curve.

### XMSS is stateful, which is a wallet problem rather than a cryptography problem

QRL's live mainnet signs with XMSS. The scheme is hash-based, conservative, and
older than any lattice standard — its security rests on hash functions alone,
which is a genuinely weaker assumption than a lattice problem, and that is a
point in its favour, not against it.

Its cost is elsewhere. The secret is a tree of one-time keys, and *which leaves
have been used* is part of the secret. Restore a wallet from a backup taken a
hundred signatures ago and it will reuse those hundred leaves; XMSS loses
security when a leaf is reused, and no care in the cryptography stops an ordinary
restore-from-backup from doing it. It is also a hard ceiling: a key can sign
2^h times and then it is spent.

ML-DSA is stateless, so a Lattica backup is a backup and a key never runs out.
QRL 2.0 moves to ML-DSA-87 for the same reason, which is the clearest evidence
that the concern is practical rather than theoretical.

What stateless costs Lattica is HD derivation. Lattice schemes have no key
homomorphism, so there is no additive tweak and no extended public key: a parent
public key cannot derive child public keys. Derivation is therefore hardened-only,
chaining the 32-byte FIPS 204 key-generation seed through a SHA3-512 PRF instead
of tweaking a scalar ([`key.h:219-229`](../src/key.h#L219-L229)). One master seed
still recovers the whole tree, but watch-only xpub wallets are impossible. This
is a property of lattice signatures, so it will be equally true of QRL 2.0 and of
Bitcoin Quantum.

### The block limit is the honest consequence of the signature size

A signature grows from 71 bytes to 2420 and a public key from 33 to 1313. A chain
that changes the signature scheme and leaves the block limit alone has cut its own
throughput by roughly a factor of eight without saying so.

Bitcoin's witness discount prices witness data at a quarter weight, on the
argument that a validating node may eventually discard it. Under ML-DSA the
witness is not an appendix to a transaction, it is nearly all of it, so the
discount would charge almost nothing for almost the entire chain and the limit
would stop describing any real resource. Lattica sets the witness scale factor to
1 and bounds a block by its serialised size alone, at 32,000,000 bytes.

The figure is derived rather than chosen: at 3856 bytes for an ordinary payment a
block admits about 8,300 of them, against about 7,100 elliptic-curve payments in a
4-million-weight-unit block. Within twenty percent — the substitution costs the
user bandwidth and disk, which it plainly does, and not throughput. The bill is
4.6 GB per day at saturation, about 170 GB per year at ten percent occupancy.

## 4. What Lattica does not have

Stated here rather than left for a reader to find.

**Almost no history.** Block 1 was mined on 11 July 2026, so the chain is weeks
old where QRL is eight years old and Bitcoin seventeen. The genesis block carries
an earlier timestamp; the chain began when it began producing blocks. Every argument here is
about design, and none of it substitutes for a chain having survived things.

**No smart contracts.** QRL 2.0 is EVM-compatible. Lattica is a payment chain
with Bitcoin's script model and nothing more.

**No migration path.** Bitcoin Quantum and BIP-360 exist so that existing coins
have somewhere to go. Lattica offers existing coins nothing.

**No independent audit.** The ML-DSA-44 and ML-KEM-768 implementations are
PQClean, reviewed upstream, but their integration here has not been audited.

**No authenticated transport.** The v2 handshake is opportunistic and
unauthenticated: confidentiality and forward secrecy against a passive observer,
not protection against an active man in the middle
([`v2cipher.h:29`](../src/v2cipher.h#L29)). This matches BIP-324's own posture.

## Sources

External figures are as published on the dates given.

- QRL mainnet and Project Zond — signature scheme, consensus, launch status:
  [theqrl.org/roadmap](https://www.theqrl.org/roadmap/) (retrieved July 2026)
- QRL launch date: [Eight Years of Building the Quantum-Safe Future](https://www.theqrl.org/blog/celebrating-8-years/)
- QRL supply, XMSS, ~3 KB transactions: [docs.theqrl.org](https://docs.theqrl.org/what-is-qrl/)
- Bitcoin Quantum — new genesis, 21 M supply, BTQ Technologies:
  [The Quantum Insider, 16 Oct 2025](https://thequantuminsider.com/2025/10/16/btq-technologies-announces-quantum-safe-bitcoin-using-nist-standardized-post-quantum-cryptography/)
- Bitcoin Quantum — Dilithium present, secp256k1 present, no KEM: read from
  [github.com/btq-ag/btq-core](https://github.com/btq-ag/btq-core/tree/master/src/crypto)
  (retrieved July 2026), not from the announcements
- Bitcoin Quantum testnet v0.3.0, BIP-360 / P2MR, five Dilithium opcodes, Mar 2026:
  [CoinDesk, 12 Jan 2026](https://www.coindesk.com/tech/2026/01/12/quantum-computing-threatens-the-usd2-trillion-bitcoin-network-btq-technologies-says-it-has-a-defense)
- FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) and their parameter sizes:
  [csrc.nist.gov/projects/post-quantum-cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- BIP-360 and Bitcoin's migration problem:
  [postquantum.com — Fixing Bitcoin](https://postquantum.com/quantum-threat-crypto/fixing-bitcoin-pqc-migration/)

Lattica's figures are this repository itself, each linked to its line, so
every one can be checked against the code rather than against this document.
