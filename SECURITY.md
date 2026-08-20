# Security Policy

## Reporting a Vulnerability

Lattica is pre-launch consensus software. Security issues — especially those
affecting consensus, the SHA3-256d proof-of-work, the ML-DSA-44 signature path,
the wallet, or the P2P network — must be disclosed responsibly and never in a
public issue, pull request, or discussion.

Report privately through GitHub:
**[Security → Report a vulnerability](https://github.com/gettessera-project/tessera/security/advisories/new)**

That channel is visible only to the maintainers until an advisory is published.

Please include enough detail to reproduce the issue. You will receive an
acknowledgement, and we will coordinate a fix and a disclosure timeline with you
before any public discussion.

## Scope

Consensus divergence, remote crashes, fund loss, key recovery, and anything that
lets a peer make a node accept an invalid block or reject a valid one are in
scope. So is the post-quantum work specifically: the ML-DSA-44 integration in
`src/pubkey.cpp` and `src/key.cpp`, the HD derivation in `CExtKey`, and the
ML-KEM-768 handshake in the v2 transport.
