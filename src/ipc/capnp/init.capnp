# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

@0x80a1032fa92dc515;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Proxy = import "/mp/proxy.capnp";
$Proxy.include("interfaces/echo.h");
$Proxy.include("interfaces/init.h");
$Proxy.include("interfaces/mining.h");
$Proxy.includeTypes("ipc/capnp/init-types.h");

using Echo = import "echo.capnp";
using Mining = import "mining.capnp";
using Rpc = import "rpc.capnp";

interface Init $Proxy.wrap("interfaces::Init") {
    construct @0 (threadMap: Proxy.ThreadMap) -> (threadMap :Proxy.ThreadMap);
    makeEcho @1 (context :Proxy.Context) -> (result :Echo.Echo);
    makeMining @3 (context :Proxy.Context) -> (result :Mining.Mining);
    makeRpc @4 (context :Proxy.Context) -> (result :Rpc.Rpc);

    # DEPRECATED: no longer supported; server returns an error.
    makeMiningOld2 @2 () -> ();
}
