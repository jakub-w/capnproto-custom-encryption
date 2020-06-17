#include <iostream>
#include <system_error>

#include <capnp/rpc-twoparty.h>

#include "messages.capnp.h"
#include "EncryptedConnection.h"
#include "InsecureChannel.h"
#include "PubkeyChannel.h"
#include "AsyncIoStreamWrapper.h"

class PlayerImpl final : public rpc::Player::Server {
  kj::Promise<void> playFrom(PlayFromContext context) final {
    return kj::READY_NOW;
  }

  kj::Promise<void> stop(StopContext context) final {
    return kj::READY_NOW;
  }

  kj::Promise<void> togglePause(TogglePauseContext context) final {
    return kj::READY_NOW;
  }

  kj::Promise<void> volume(VolumeContext context) {
    return kj::READY_NOW;
  }

  kj::Promise<void> seek(SeekContext context) {
    context.getResults().getResponse().setCode(7);
    return kj::READY_NOW;
  }

  kj::Promise<void> ping(PingContext context) {
    return kj::READY_NOW;
  }
};

int main() {
  auto ioContext = kj::setupAsyncIo();

  capnp::TwoPartyServer server{kj::heap<PlayerImpl>()};

  auto listen_address = ioContext.provider->getNetwork()
                        .parseAddress("127.0.0.1").wait(ioContext.waitScope);
  auto listener = listen_address->listen();
  auto listenPromise = server.listen(*listener);

  auto conn_address = ioContext.provider->getNetwork()
                      .parseAddress("127.0.0.1", listener->getPort())
                      .wait(ioContext.waitScope);
  auto connection = conn_address->connect().wait(ioContext.waitScope);
  // auto secure_connection =
  //     EncryptedConnection<PubkeyChannel<AsyncIoStreamWrapper>>(
  //         kj::mv(connection));
  auto secure_connection =
      makeEncryptedConnection<PubkeyChannel>(kj::mv(connection));
  auto ec = secure_connection.connect();
  if (ec) {
    std::cerr << "Handshake failed: " << ec.message() << '\n';
    return 1;
  }

  // TODO: Here I should create a new connection to connect to the first one.
  capnp::TwoPartyClient client{secure_connection};
  auto cap = client.bootstrap().castAs<rpc::Player>();

  auto request = cap.seekRequest();

  auto promise = request.send().then(
      [](capnp::Response<rpc::Player::SeekResults> results){
        std::cout << results.toString().flatten().cStr()
                  << '\n';
        // return kj::Promise<uint8_t>(results.getResponse().getCode());
      });

  promise.wait(ioContext.waitScope);

  return 0;
}

// TODO: Put stuff into namespaces
