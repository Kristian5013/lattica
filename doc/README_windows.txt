Lattica
========

Intro
-----
Lattica is a post-quantum cryptocurrency. Building upon the
Bitcoin Core architecture, it replaces ECDSA signatures with ML-DSA-44 (FIPS 204)
and secures its chain with the SHA3-256d proof-of-work. This is experimental
software.

Setup
-----
Lattica is the original Lattica client and it builds the backbone of the
network. It downloads and, by default, stores the entire history of Lattica
transactions, which requires a few hundred gigabytes of disk space once the
network has matured. Depending on the speed of your computer and network
connection, the synchronization process can take a while to complete.

To start Lattica with a graphical user interface, run lattica-qt.exe. The
headless daemon (latticad.exe) and the command-line client (lattica-cli.exe)
are installed alongside it.

Data is stored in %LOCALAPPDATA%\Lattica by default. A heavily-commented
example configuration file is provided in share\examples\lattica.conf; copy it
into the data directory as lattica.conf and edit it to change settings.
