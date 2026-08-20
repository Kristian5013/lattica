# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

@0x9c3505dc45e146ac;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Common = import "common.capnp";
using Proxy = import "/mp/proxy.capnp";
$Proxy.include("interfaces/rpc.h");
$Proxy.includeTypes("ipc/capnp/rpc-types.h");

interface Rpc $Proxy.wrap("interfaces::Rpc") {
    executeRpc @0 (context :Proxy.Context, request :Text, uri :Text, user :Text) -> (result :Text);
}
