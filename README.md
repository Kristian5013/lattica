<div align="center">
  <img src="src/qt/res/icons/lattica.png" alt="Lattica" width="120" />

  <h1>Lattica</h1>

  <p><strong>A post-quantum cryptocurrency built on the Bitcoin Core architecture.</strong></p>

  [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](COPYING)
</div>

---

Lattica keeps the Bitcoin Core design — a UTXO ledger, Script, full-node
validation, a peer-to-peer network, a built-in wallet — and adds the signature
schemes a quantum computer does not break.

That addition is the whole point. In March 2026 a joint whitepaper from Google
Quantum AI, the Ethereum Foundation and Stanford put a number on it: the 256-bit
elliptic-curve discrete logarithm, the problem every Bitcoin signature rests on,
falls in minutes to fewer than half a million physical qubits
([arXiv:2603.28846](https://arxiv.org/abs/2603.28846)). NIST has separately
scheduled ECDSA for deprecation after 2030 and disallowance after 2035. Lattica
starts on the other side of that line.

### What is different from Bitcoin

- **Three signature schemes, and the witness version says which.** Base, P2SH
  and witness v0 and v1 are secp256k1, byte for byte Bitcoin's — including
  Taproot. Witness v2 is post-quantum: **Falcon-512** (FIPS 206 draft) or
  **ML-DSA-44** (FIPS 204), both vendored from PQClean. Nothing distinguishes
  the two lattice schemes in the address, because a witness v2 address is a
  hash; what tells them apart is the length of the key that spends it, and only
  the wallet holding that key knows it in advance.
- **Encrypted transport: ML-KEM-768** (FIPS 203) in the v2 P2P handshake, in
  place of the elliptic-curve exchange of BIP324. On by default, so the wire is
  covered as well as the coins.
- **Hashing: SHA3-256** (FIPS 202) throughout — block and transaction ids,
  Merkle trees — and **SHA3-256d** for proof of work. Address and script hashes
  are `Hash160 = RIPEMD160(SHA3-256)`, Bitcoin's two-stage shape over a SHA3
  inner digest, so the short hash is not a prefix of the long one.
- **No witness discount.** `WITNESS_SCALE_FACTOR` is 1: a vbyte is a byte and
  weight is serialized size. Segwit's discount was priced for 72-byte
  signatures; it is not obvious what it should mean for a 2420-byte one, so it
  means nothing. The block is 32 MB instead, which is where the room comes from.
- **Everything else is deliberately unchanged.** The 2016-block difficulty
  retarget, the ten-minute target, the 210 000-block halving, Script. A
  post-quantum chain is already enough novelty for one project.

### What it costs, measured

A lattice signature is large and no amount of engineering makes it small. These
are measured, not estimated — the wallet's own figures for a spend, and for a
whole one-input two-output transaction:

| | input | transaction | per 32 MB block |
| --- | ---: | ---: | ---: |
| secp256k1 (P2WPKH) | 149 B | 222 B | 144 144 |
| Falcon-512 | 1 612 B | 1 686 B | 18 979 |
| ML-DSA-44 | 3 781 B | 3 855 B | 8 300 |

An ML-DSA-44 spend is 25× a curve spend and a Falcon-512 spend is 11×. The block
is 32× Bitcoin's, so the throughput that comes out the other side is **1.8×
Bitcoin's in ML-DSA-44 and 4.2× in Falcon-512** — against roughly 4 500
transactions in a 1 MB-equivalent Bitcoin block. The signatures cost more; the
chain buys the room back and then some.

Falcon-512 is the cheaper of the two by a factor of two and a half. ML-DSA-44 is
the wallet's default anyway, because Falcon signs by sampling a discrete
Gaussian in floating point and stands on a draft standard, where ML-DSA is final
and signs in integers. Verification of both is integer-only, so consensus does
not turn on that choice — a signing key does. Falcon stays one `-addresstype`
away.

## Status

**Pre-launch.** There is no public network yet. Mainnet genesis is mined and
dated 19 August 2026, and the node runs: it mines, hands out addresses of all
six types, and spends from every one of them. What has not happened is two nodes
talking to each other outside a laboratory, so the identity values in
`src/kernel/chainparams.cpp` — network magic, ports, address prefixes, bech32
HRPs — are still marked provisional and can be revised until the chain has
weight behind it. After that they cannot.

The chain begins at **difficulty 1** — the same target Bitcoin's genesis used —
so an ordinary CPU can mine from the first block.

## Address types

Six, and the wallet will hand out any of them. The first four are Bitcoin's,
unchanged; the last two are the reason this project exists.

| `-addresstype` | Example (mainnet) | Script | Scheme |
| --- | --- | --- | --- |
| `legacy` | `Le6qc6Lj2Jxb…` | P2PKH | secp256k1 |
| `p2sh-segwit` | `MMxTBs9ADojX…` | P2SH-P2WPKH | secp256k1 |
| `bech32` | `la1qhf08uylmp…` | witness v0 | secp256k1 |
| `bech32m` | `la1pfksejfp7n…` | witness v1, Taproot | secp256k1 |
| `falcon512` | `la1zjm3p4xspf…` | witness v2 | Falcon-512 |
| `mldsa44` | `la1zkq6ceg378…` | witness v2 | ML-DSA-44 |

The default is `mldsa44`. Both lattice types encode identically — `la1z…`, where
`z` is bech32m's character for witness version 2 — because both are a 20-byte
hash under that version. The key itself, 897 bytes or 1312, never appears in an
address; it appears in the witness, when the output is spent.

## Binaries

| Binary | Purpose |
| --- | --- |
| `latticad` | Headless full node and wallet daemon |
| `lattica-cli` | JSON-RPC command-line client |
| `lattica-qt` | Desktop GUI wallet (Qt Widgets) |
| `lattica-miner` | Standalone multi-threaded CPU miner |
| `lattica-miner-gpu` | Standalone OpenCL GPU miner (built when an OpenCL SDK is found) |
| `lattica-wallet` | Offline wallet tool |
| `lattica-tx` | Offline raw-transaction tool |
| `lattica-util` | Offline utility tool |

## Building

CMake and a C++20 compiler (GCC ≥ 12 or Clang ≥ 15). Per-platform instructions
and the dependency list are in [`doc/build-unix.md`](doc/build-unix.md),
[`doc/build-windows.md`](doc/build-windows.md) and
[`doc/dependencies.md`](doc/dependencies.md).

```bash
# deps (Ubuntu 24.04): g++-14 cmake libboost-dev libsqlite3-dev libzmq3-dev
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build              # unit tests
```

The wallet and ZMQ notifications are on by default. The Qt GUI
(`-DENABLE_GUI=ON`) and multiprocess IPC (`-DENABLE_IPC=ON`, Unix only) are
opt-in.

## Running

```bash
# regtest — a private network for development
latticad -regtest -daemon
lattica-cli -regtest createwallet w
lattica-cli -regtest getnewaddress                 # a witness v2 address
lattica-cli -regtest getnewaddress "" falcon512    # or ask for the cheaper scheme
lattica-cli -regtest -generate 101
lattica-cli -regtest sendtoaddress <address> 1
```

## Mining

`lattica-miner` fetches work over JSON-RPC, grinds SHA3-256d on every core and
submits the block. `lattica-miner-gpu` is the same miner against an OpenCL
device; it is built only when an OpenCL SDK is present, and the node never
depends on it. Both grind the consensus `CBlockHeader::GetPoWHash`, so a nonce
either miner finds is one the node accepts.

```bash
lattica-miner -benchmark                       # this machine's hashrate
lattica-miner -address=<your address>          # mine to a running latticad
lattica-miner -address=<addr> -threads=4       # or pin the thread count
```

The node's own `generatetoaddress` RPC exists too, but it is single-threaded and
gives up after a million attempts by default — about 0.02% of what one block
needs at difficulty 1. It is meant for regtest, not for mining.

## Network parameters

| | mainnet | testnet | regtest |
| --- | --- | --- | --- |
| P2P port | 12333 | 22333 | 22444 |
| RPC port | 12332 | 22332 | 22443 |
| base58 prefix | `L` (P2PKH), `M` (P2SH) | `t`, `x` | `t`, `x` |
| bech32 HRP | `la` | `tl` | `lart` |
| Data directory | `~/.lattica` | | |

## Repository layout

```
src/            node, consensus, wallet, P2P, RPC, crypto
  secp256k1/    vendored libsecp256k1, for the base and witness v0/v1 schemes
  mldsa44/      vendored FIPS 204 signature implementation
  falcon512/    vendored FIPS 206 draft signature implementation
  mlkem768/     vendored FIPS 203 key encapsulation
  qt/           the Qt Widgets GUI
  test/         unit tests (run via ctest)
tools/          offline helpers, including the genesis miner
doc/            build, design and interface documentation
contrib/        tooling and helper scripts
```

## Documentation

Start at [`doc/README.md`](doc/README.md). Design notes are under
[`doc/design/`](doc/design/).

## Contributing and security

Developer notes and coding style: [`doc/developer-notes.md`](doc/developer-notes.md).

Report vulnerabilities as described in [`SECURITY.md`](SECURITY.md) — never in a
public issue.

## License

MIT. See [`COPYING`](COPYING).
