# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

@0xcd2c6232cb484a28;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Proxy = import "/mp/proxy.capnp";
$Proxy.includeTypes("ipc/capnp/common-types.h");

struct BlockRef $Proxy.wrap("interfaces::BlockRef") {
    hash @0 :Data;
    height @1 :Int32;
}
