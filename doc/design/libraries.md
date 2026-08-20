# Libraries

| Name                     | Description |
|--------------------------|-------------|
| *liblattica_cli*         | RPC client functionality used by *lattica-cli* executable |
| *liblattica_common*      | Home for common functionality shared by different executables and libraries. Similar to *liblattica_util*, but higher-level (see [Dependencies](#dependencies)). |
| *liblattica_consensus*   | Consensus functionality used by *liblattica_node* and *liblattica_wallet*. |
| *liblattica_crypto*      | Hardware-optimized functions for data encryption, hashing, message authentication, and key derivation. |
| *liblatticaqt*           | GUI functionality used by *lattica-qt* and *lattica-gui* executables. |
| *liblattica_ipc*         | IPC functionality used by *lattica-node* and *lattica-gui* executables to communicate when [`-DENABLE_IPC=ON`](multiprocess.md) is used. |
| *liblattica_node*        | P2P, RPC and validation functionality used by *latticad* and *lattica-qt* executables. |
| *liblattica_util*        | Home for common functionality shared by different executables and libraries. Similar to *liblattica_common*, but lower-level (see [Dependencies](#dependencies)). |
| *liblattica_wallet*      | Wallet functionality used by *latticad* and *lattica-wallet* executables. |
| *liblattica_zmq*         | [ZeroMQ](../zmq.md) functionality used by *latticad* and *lattica-qt* executables. |

(Unlike Bitcoin Core, Lattica has no separate `liblattica_kernel` — validation
lives in *liblattica_node* — and no `liblattica_wallet_tool`; the wallet tool
code is part of the *lattica-wallet* executable.)

## Conventions

- Most libraries are internal libraries and have APIs which are completely unstable! There are few or no restrictions on backwards compatibility or rules about external dependencies.

- Generally each library should have a corresponding source directory and namespace. Source code organization is a work in progress, so it is true that some namespaces are applied inconsistently, and if you look at [`add_library(lattica_* ...)`](../../src/CMakeLists.txt) lists you can see that many libraries pull in files from outside their source directory. But when working with libraries, it is good to follow a consistent pattern like:

  - *liblattica_node* code lives in `src/node/` in the `node::` namespace
  - *liblattica_wallet* code lives in `src/wallet/` in the `wallet::` namespace
  - *liblattica_ipc* code lives in `src/ipc/` in the `ipc::` namespace
  - *liblattica_util* code lives in `src/util/` in the `util::` namespace
  - *liblattica_consensus* code lives in `src/consensus/` in the `Consensus::` namespace

## Dependencies

- Libraries should minimize what other libraries they depend on, and only reference symbols following the arrows shown in the dependency graph below:

<table><tr><td>

```mermaid

%%{ init : { "flowchart" : { "curve" : "basis" }}}%%

graph TD;

lattica-cli[lattica-cli]-->liblattica_cli;

latticad[latticad]-->liblattica_node;
latticad[latticad]-->liblattica_wallet;

lattica-qt[lattica-qt]-->liblattica_node;
lattica-qt[lattica-qt]-->liblatticaqt;
lattica-qt[lattica-qt]-->liblattica_wallet;

lattica-wallet[lattica-wallet]-->liblattica_wallet;

liblattica_cli-->liblattica_util;
liblattica_cli-->liblattica_common;

liblattica_consensus-->liblattica_crypto;

liblattica_common-->liblattica_consensus;
liblattica_common-->liblattica_crypto;
liblattica_common-->liblattica_util;

liblattica_node-->liblattica_consensus;
liblattica_node-->liblattica_crypto;
liblattica_node-->liblattica_common;
liblattica_node-->liblattica_util;

liblatticaqt-->liblattica_common;
liblatticaqt-->liblattica_util;

liblattica_util-->liblattica_crypto;

liblattica_wallet-->liblattica_common;
liblattica_wallet-->liblattica_crypto;
liblattica_wallet-->liblattica_util;

classDef bold stroke-width:2px, font-weight:bold, font-size: smaller;
class lattica-qt,latticad,lattica-cli,lattica-wallet bold
```
</td></tr><tr><td>

**Dependency graph**. Arrows show linker symbol dependencies. *Crypto* lib depends on nothing. *Util* lib is depended on by everything.

</td></tr></table>

- The graph shows what _linker symbols_ (functions and variables) from each library other libraries can call and reference directly, but it is not a call graph. For example, there is no arrow connecting *liblattica_wallet* and *liblattica_node* libraries, because these libraries are intended to be modular and not depend on each other's internal implementation details. But wallet code is still able to call node code indirectly through the `interfaces::Chain` abstract class in [`interfaces/chain.h`](../../src/interfaces/chain.h) and node code calls wallet code through the `interfaces::ChainClient` and `interfaces::Chain::Notifications` abstract classes in the same file. In general, defining abstract classes in [`src/interfaces/`](../../src/interfaces/) can be a convenient way of avoiding unwanted direct dependencies or circular dependencies between libraries.

- *liblattica_crypto* should be a standalone dependency that any library can depend on, and it should not depend on any other libraries itself.

- *liblattica_consensus* should only depend on *liblattica_crypto*, and all other libraries besides *liblattica_crypto* should be allowed to depend on it.

- *liblattica_util* should be a standalone dependency that any library can depend on, and it should not depend on other libraries except *liblattica_crypto*. It provides basic utilities that fill in gaps in the C++ standard library and provide lightweight abstractions over platform-specific features.

- *liblattica_common* is a home for miscellaneous shared code used by different Lattica applications. It should not depend on anything other than *liblattica_util*, *liblattica_consensus*, and *liblattica_crypto*.

- GUI, node, and wallet code internal implementations should all be independent of each other, and the *liblatticaqt*, *liblattica_node*, *liblattica_wallet* libraries should never reference each other's symbols. They should only call each other through [`src/interfaces/`](../../src/interfaces/) abstract interfaces.
