# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

@0x8ac57bea1876b2db;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("ipc::capnp::messages");

using Proxy = import "/mp/proxy.capnp";
$Proxy.include("interfaces/echo.h");
$Proxy.includeTypes("ipc/capnp/echo-types.h");

interface Echo $Proxy.wrap("interfaces::Echo") {
    destroy @0 (context :Proxy.Context) -> ();
    echo @1 (context :Proxy.Context, echo: Text) -> (result :Text);
}
