@0xe640b12145984b16;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("rpc");

struct TestIntStruct {
    int @0 :Int32;
}

struct TestStruct {
    int @0 :Int32;
    text @1 :Text;
}

interface Test {
    getTestStruct @0 (int :TestIntStruct) -> (response :TestStruct);
}