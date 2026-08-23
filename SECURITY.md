# Security Policy

## Reporting a Vulnerability

Lattica is pre-launch consensus software. Security issues — especially those
affecting consensus, the SHA3-256d proof-of-work, either post-quantum signature
path, the wallet, or the P2P network — must be disclosed responsibly and never
in a public issue, pull request, or discussion.

Report privately, by either route:

- **Email:** pilatovichkristian2@gmail.com
- **GitHub:** [Security → Report a vulnerability](https://github.com/Kristian5013/lattica/security/advisories/new),
  which is visible only to the maintainers until an advisory is published.

Please include enough detail to reproduce the issue. You will receive an
acknowledgement, and we will coordinate a fix and a disclosure timeline with you
before any public discussion.

## Scope

Consensus divergence, remote crashes, fund loss, key recovery, and anything that
lets a peer make a node accept an invalid block or reject a valid one are in
scope.

So is the post-quantum work specifically, which is where this codebase departs
from a well-reviewed design and therefore where the interesting mistakes are:

- The **Falcon-512** and **ML-DSA-44** integrations in `src/pubkey.cpp` and
  `src/key.cpp`, including the rule that the length of a key names its scheme.
- **Witness v2**, which is what makes a lattice signature spendable: the
  scheme-to-version binding in `SchemeAllowedForSigVersion`
  (`src/script/interpreter.cpp`), and the raised element bound
  `MAX_SCRIPT_ELEMENT_SIZE_V2`.
- **HD derivation** in `CExtKey` (`src/key.cpp`), which is hardened at every
  step for all three schemes and mixes the scheme into the master node's
  preimage, so one seed yields three unrelated trees.
- The **ML-KEM-768** handshake in the v2 transport (`src/v2cipher.h`,
  `src/net.cpp`).
- Anything that lets a witness v2 output be created but not spent, or spent by
  someone who does not hold the key.

Reports about the secp256k1 paths are equally welcome; those are Bitcoin Core's
code and a finding there is likely to matter upstream as well.
