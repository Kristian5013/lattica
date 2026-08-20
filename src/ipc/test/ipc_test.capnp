# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.

@0xd71b0fc8727fdf83;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("gen");

using Proxy = import "/mp/proxy.capnp";
$Proxy.include("ipc/test/ipc_test.h");
$Proxy.includeTypes("ipc/test/ipc_test_types.h");

interface FooInterface $Proxy.wrap("FooImplementation") {
    add @0 (a :Int32, b :Int32) -> (result :Int32);
    passOutPoint @1 (arg :Data) -> (result :Data);
    passUniValue @2 (arg :Text) -> (result :Text);
    passTransaction @3 (arg :Data) -> (result :Data);
    passVectorChar @4 (arg :Data) -> (result :Data);
    passScript @5 (arg :Data) -> (result :Data);
}
