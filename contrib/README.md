Repository Tools
---------------------

### [Developer tools](/contrib/devtools) ###
Specific tools for developers working on this repository.

### [Linearize](/contrib/linearize) ###
Construct a linear, no-fork, best version of the blockchain.

### [Qos](/contrib/qos) ###

A Linux bash script that will set up traffic control (tc) to limit the outgoing bandwidth for connections to the Lattica network. This means one can have an always-on latticad instance running, and another local latticad/lattica-qt instance which connects to this node and receives blocks from it.

### [Seeds](/contrib/seeds) ###
Utility to generate the chainparams_seed[] arrays that are compiled into the client.

### [ASMap](/contrib/asmap) ###
Utilities to analyze and process asmap files.

Node Tools
---------------------

### [Init](/contrib/init) ###
Sample configuration files for systemd, OpenRC, Upstart, CentOS init and macOS launchd to run latticad as a service.

### [ZMQ](/contrib/zmq) ###
A ZeroMQ subscriber example for the `-zmqpub*` notifications.

Command Line Tools
---------------------

### [Completions](/contrib/completions) ###
Shell completions for bash and fish.
