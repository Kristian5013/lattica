# Fuzzing

Unit tests check what someone thought to check. A fuzzer checks what nobody
thought of, which on a chain is the more dangerous half: every deserializer and
every signature verifier runs on bytes a stranger chose, before any rule has had
a chance to reject them.

That matters more here than it does on Bitcoin. Verifying a witness v2 signature
does not stay in C++ — it hands the public key and the signature to PQClean's
Falcon-512 or ML-DSA-44, about fifteen thousand lines of vendored C with fifty-
nine `memcpy` and fourteen `malloc` between them. Every node on the network runs
that code on every input of every block it is offered. A bounds mistake there is
not a wrong answer; it is undefined behaviour on all nodes at once. Nothing about
the language prevents it. Only evidence does, and this is where the evidence
comes from.

## Building

Clang only: libFuzzer ships with clang and has no GCC counterpart. The build is
a directory of its own, because the instrumentation covers the whole node — the
point is to see inside `lattica_node` and inside the vendored C, not inside the
three files of the harness — and an instrumented binary is not the one anyone
should run a node with.

```bash
cmake -B build-fuzz -DBUILD_FUZZ_BINARY=ON \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz --target fuzz -j"$(nproc)"
```

The ordinary `cmake -B build` is untouched and keeps using GCC.

## Running

One binary holds every target; `FUZZ` names which one runs. Linking the node
stack once rather than once per target is what keeps a growing set buildable.

```bash
# what targets exist
FUZZ= ./build-fuzz/fuzz

# one target, until you stop it, keeping what it learns in a corpus directory
FUZZ=pubkey ./build-fuzz/fuzz test/fuzz/corpus/pubkey

# every target for a minute each, which is the form that fits into a change
test/fuzz/run.sh ./build-fuzz/fuzz 60
```

The bound is the point. An unbounded fuzzer is a thing that gets run once; a
fuzzer that finishes in a known number of minutes is a thing that runs on every
change, and a fault found on the day it is written is worth more than the same
fault found thoroughly a year later.

The corpus persists, so each run starts from everything previous runs learned.
Keep it out of the repository — inputs are cheap to regenerate and grow without
bound.

## When something is found

libFuzzer writes the offending input next to the corpus as `crash-<sha1>` and
prints the stack. Reproduce it deterministically:

```bash
FUZZ=<target> ./build-fuzz/fuzz crash-<sha1>
```

A crashing input belongs in `src/test/` as a regression check with the bytes
written out literally, so the fault stays fixed even if the corpus is discarded.

## Targets

| Target | What it feeds |
| --- | --- |
| `pubkey` | arbitrary bytes as a public key and a signature, through `CPubKey::Verify` into the vendored C |
| `pubkey_verify_real` | a key that really is a key, so verification runs past the early rejects and into the body of the implementation |
| `transaction` | `CTransaction` deserialization, and that its encoding is the only one |
| `block_header` | both hashes of a header, including `GetPoWHash` |
| `block` | a whole block |
| `script` | script walking, the solver, and destination extraction |
| `address_decode` | base58 and bech32 address strings, and the extended-key readers |
| `descriptor_parse` | the descriptor language, and that what parses prints back the same |

Adding one is ten lines: write `FUZZ_TARGET(name) { ... }` in a file under
`src/test/fuzz/`, list the file in that directory's `CMakeLists.txt`. The macro
registers it; nothing else needs to know it exists.

## What a target should assert

Almost nothing. Rejecting the input is the ordinary case and is not a finding —
most random bytes are not a transaction. What a target is looking for is what no
return value can express: a read past the end of a buffer, a leak, an abort. The
sanitizers report those.

There is one property worth asserting explicitly, and `transaction` does it: an
object that has an id must have exactly one encoding. Two encodings of one
transaction are two ids for one transaction, and two ids are a chain split. A
deserializer that throws is behaving; a deserializer that accepts bytes it would
not itself have written is not.
