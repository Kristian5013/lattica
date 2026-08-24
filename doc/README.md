Lattica
=============

Setup
---------------------
Lattica is a post-quantum UTXO cryptocurrency: it signs with ML-DSA-44 (FIPS 204)
instead of an elliptic curve, hashes with SHA3-256, and secures its chain with the
SHA3-256d proof of work. The node downloads and, by default, stores the entire
history of Lattica transactions; depending on the speed of your computer and
network connection, the synchronization process can take some time.

To build Lattica from source, see the build notes below.

Running
---------------------
The following are some helpful notes on how to run Lattica on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/lattica-qt` (GUI) or
- `bin/latticad` (headless)

### Windows

Unpack the files into a directory, and then run `lattica-qt.exe`.

Building
---------------------
The following are developer notes on how to build Lattica on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)

Development
---------------------
The repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Fuzzing](fuzzing.md)
- [Productivity Notes](productivity.md)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

### Resources
* Project source and issue tracker: [github.com/bitcoin/bitcoin](https://github.com/bitcoin/bitcoin).

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [asmap Data](asmap-data.md)
- [assumeutxo](assumeutxo.md)
- [CJDNS Support](cjdns.md)
- [Files](files.md)
- [lattica.conf Configuration File](lattica-conf.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [Managing Wallets](managing-wallets.md)
- [Multiprocess](multiprocess.md)
- [P2P bad ports definition and list](p2p-bad-ports.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Transaction Relay Policy](policy/README.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
