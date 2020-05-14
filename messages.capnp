@0xce8607fed1e6ae36;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("rpc");

struct StreamingPort {
    port @0 :UInt16;
}

struct VolumeMessage {
    volume @0 :Text;
}

struct SeekMessage {
    seconds @0 :UInt32;
}

struct MessageResponse {
    code @0 :UInt8;
}

struct TimeInterval {
    milliseconds @0 :UInt32;
}

struct SongMetadata {
    title @0 :Text;
    album @1 :Text;
    artist @2 :Text;
}

struct TimeInfo {
    totalTime @0 :Float64;
    currentTime @1 :Float64;
    remainingTime @2 :Float64;
    remainingPlaytime @3 :Float64;
    volume @4 :Int32;

    playbackState @5: UInt8;
}


interface Player {
    playFrom @0 (port :StreamingPort) -> (response :MessageResponse);
    stop @1 () -> (response :MessageResponse);
    togglePause @2 () -> (response :MessageResponse);
    volume @3 (volume :VolumeMessage) -> (response :MessageResponse);
    seek @4 (seek :SeekMessage) -> (response :MessageResponse);
    ping @5 ();
    # timeInfoStream @ (stream  ) -> (stream TimeInfo);
}