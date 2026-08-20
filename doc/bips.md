BIPs that are implemented by Lattica
=====================================

Lattica descends from Bitcoin Core and inherits most of its peer-to-peer and
consensus machinery, so a large number of Bitcoin Improvement Proposals (BIPs)
apply unchanged. The two foundational differences change which BIPs are relevant:

* **Signatures are ML-DSA-44 (FIPS 204), not ECDSA/Schnorr.** There is no
  secp256k1 elliptic curve anywhere in Lattica, so every BIP that depends on
  one (EC HD wallets, DER encoding, Schnorr/Taproot, MuSig, the BIP-324 v2
  transport) does not apply.
* **Consensus hashing is single SHA3-256, not double SHA-256.** Mechanisms that
  are otherwise unchanged from Bitcoin (e.g. the BIP-143 segwit sighash) are
  computed with SHA3-256 instead.

All soft forks are active from the genesis block; there is no deployment
signalling history.

Supported
---------

Inherited from the Bitcoin Core port and active in Lattica:

* **BIP 11**: Multisig (`OP_CHECKMULTISIG`) is available in the script interpreter.
* **BIP 13 / BIP 16**: Pay-to-Script-Hash (`OP_HASH160`, using Hash160 = RIPEMD160(SHA3-256)).
* **BIP 14**: The peer subversion string is `/Lattica:<version>/`.
* **BIP 21**: URI scheme, using the `lattica:` scheme.
* **BIP 22 / BIP 23**: `getblocktemplate` and its mutations/proposals.
* **BIP 30**: Duplicate-transaction handling.
* **BIP 31**: `pong` message.
* **BIP 34**: Block height in the coinbase.
* **BIP 35**: `mempool` message.
* **BIP 37**: Bloom filtering of connections (and `NODE_BLOOM`, BIP 111).
* **BIP 42**: Finite block subsidy.
* **BIP 65**: `OP_CHECKLOCKTIMEVERIFY`.
* **BIP 68 / BIP 112 / BIP 113**: Relative lock-time, `OP_CHECKSEQUENCEVERIFY`,
  and median-time-past as endpoint for lock-time.
* **BIP 130**: `sendheaders` direct headers announcement.
* **BIP 133**: `feefilter` message.
* **BIP 141 / BIP 143 / BIP 144 / BIP 145 / BIP 147**: Segregated Witness — the
  witness program format, transaction serialization and the witness sighash.
  Lattica uses witness-only outputs (P2WPKH); the BIP-143 sighash is computed
  with SHA3-256, and `CHECKSIG` verifies an ML-DSA-44 signature over it.
* **BIP 152**: Compact block relay.
* **BIP 155**: `addrv2` address gossip and serialization.
* **BIP 157 / BIP 158**: Compact block filters (the basic filter index).
* **BIP 159**: `NODE_NETWORK_LIMITED` service bit.
* **BIP 173**: Bech32 addresses, with the human-readable parts `fc` (mainnet),
  `tf` (testnet) and `fcrt` (regtest). This is the only address format.

Not implemented
---------------

Either replaced by Lattica's post-quantum design or dropped:

* **BIP 32 / BIP 39 / BIP 44 / BIP 49 / BIP 84 / BIP 86**: Hierarchical
  deterministic wallets. Lattica uses a native HD keystore built on ML-DSA-44
  (hardened-only derivation via a seeded keygen), not secp256k1 BIP-32.
* **BIP 66**: Strict DER signatures. ML-DSA-44 signatures have a fixed FIPS 204
  encoding, not DER.
* **BIP 70**: Payment Protocol — removed (it relies on X.509/EC).
* **BIP 174**: Partially Signed Bitcoin Transactions (PSBT) — not ported.
* **BIP 324**: v2 encrypted P2P transport — requires secp256k1 ellswift. Lattica
  currently uses the v1 plaintext transport; a ML-KEM-768 based transport is a
  separate line of work.
* **BIP 325**: Signet — Lattica has no signet network.
* **BIP 327**: MuSig2; **BIP 340 / BIP 341 / BIP 342**: Schnorr signatures and
  Taproot — all require an elliptic curve.
* **BIP 176**: "Bits" denomination — Lattica's units are LTA / mLTA / µLTA / sat.
