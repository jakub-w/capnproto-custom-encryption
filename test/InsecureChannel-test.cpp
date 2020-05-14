#include <condition_variable>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>
#include <capnp/rpc-twoparty.h>

#include "test.capnp.h"

#include "../InsecureChannel.h"
#include "../EncryptedConnection.h"
#include "../PubkeyChannel.h"
#include "../AsyncIoStreamWrapper.h"

class TestImpl final : public rpc::Test::Server {
  kj::Promise<void> getTestStruct(GetTestStructContext context) final {
    int request_int = context.getParams().getInt().getInt();

    auto builder = context.getResults().getResponse();
    builder.setInt(request_int);
    builder.setText(std::to_string(request_int));

    return kj::READY_NOW;
  }
};

// TODO: Move it to EncryptedConnection-test.cpp, we should mock channels.
TEST(InsecureChannel, TestTest) {
  auto server_thread = std::thread(
      [&]{
        auto ioContext = kj::setupAsyncIo();
        auto listen_address =
            ioContext.provider->getNetwork()
            .parseAddress("127.0.0.1", 7245).wait(ioContext.waitScope);
        auto listener = listen_address->listen();

        auto secure_listener =
            makeEncryptedReceiver<InsecureChannel>(kj::mv(listener));
        auto secure_stream =
            secure_listener.accept().wait(ioContext.waitScope);

        // auto stream = listener->accept().wait(ioContext.waitScope);

        // auto secure_stream =
        //     EncryptedConnection<InsecureChannel<AsyncIoStreamWrapper>>(
        //         kj::mv(stream));

        char buffer[5]; buffer[4] = '\0';
        size_t bytes =
            secure_stream->tryRead(buffer, 4, 4).wait(ioContext.waitScope);
        EXPECT_EQ((size_t)4, bytes);
        EXPECT_STREQ("ABCD", buffer);
      });
  auto client_thread = std::thread(
      [&]{
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        auto ioContext = kj::setupAsyncIo();
        auto connect_address =
            ioContext.provider->getNetwork()
            .parseAddress("127.0.0.1", 7245).wait(ioContext.waitScope);
        auto connection = connect_address->connect()
                          .wait(ioContext.waitScope);
        auto secure_connection =
            makeEncryptedConnection<InsecureChannel>(kj::mv(connection));
        secure_connection.connect(); // FIXME: Do it implicitly?

        char buffer[5] = "ABCD";
        secure_connection.write(buffer, 4).wait(ioContext.waitScope);
      });

  if (server_thread.joinable()) {
    server_thread.join();
  }
  if (client_thread.joinable()) {
    client_thread.join();
  }
}

TEST(InsecureChannel, TwoWayConnection) {
  kj::Own<kj::PromiseFulfillerPair<bool>> exitPromisePair;
  const kj::Executor* executor;

  auto server_thread = std::thread(
      [&]{
        auto ioContext = kj::setupAsyncIo();
        exitPromisePair = kj::heap(kj::newPromiseAndFulfiller<bool>());
        executor = &kj::getCurrentThreadExecutor();

        auto listen_address =
            ioContext.provider->getNetwork()
            .parseAddress("127.0.0.1", 7245).wait(ioContext.waitScope);
        auto secure_address =
            EncryptedNetworkAddress<InsecureChannel<AsyncIoStreamWrapper>>(
                kj::mv(listen_address));
        // auto listener = listen_address->listen();
        // std::this_thread::sleep_for(std::chrono::milliseconds(20));
        auto listener = secure_address.listen();
        // auto secure_listener =
            // makeEncryptedReceiver<PubkeyChannel>(kj::mv(listener));
        // EncryptedConnectionReceiver<PubkeyChannel<>

        capnp::TwoPartyServer server{kj::heap<TestImpl>()};
        auto listenPromise = server.listen(*listener);

        exitPromisePair->promise.wait(ioContext.waitScope);
      });

  auto client_thread = std::thread(
      [&]{
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        auto ioContext = kj::setupAsyncIo();
        auto connect_address =
            ioContext.provider->getNetwork()
            .parseAddress("127.0.0.1", 7245).wait(ioContext.waitScope);
        auto connection = connect_address->connect()
                          .wait(ioContext.waitScope);
        auto secure_connection =
            EncryptedConnection<InsecureChannel<AsyncIoStreamWrapper>>(
                kj::mv(connection));
        secure_connection.connect(); // FIXME: Do it implicitly?

        capnp::TwoPartyClient client{secure_connection};
        auto cap = client.bootstrap().castAs<rpc::Test>();

        auto request = cap.getTestStructRequest();
        auto builder = request.getInt();
        builder.setInt(10);

        auto promise = request.send().then(
            [&](capnp::Response<rpc::Test::GetTestStructResults> results){
              auto reader = results.getResponse();
              EXPECT_EQ(10, reader.getInt());
              EXPECT_STREQ("10", reader.getText().cStr());
            });

        promise.wait(ioContext.waitScope);
        executor->executeSync(
            [&]{ exitPromisePair->fulfiller->fulfill(true); });
      });


  if (server_thread.joinable()) {
    server_thread.join();
  }
  if (client_thread.joinable()) {
    client_thread.join();
  }
}
