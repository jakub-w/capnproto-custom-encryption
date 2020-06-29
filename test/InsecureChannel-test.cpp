#include <thread>

#include <gtest/gtest.h>
#include <capnp/rpc-twoparty.h>

#include "test.capnp.h"

#include "../InsecureChannel.h"
#include "../EncryptedConnection.h"
#include "../PubkeyChannel.h"
#include "../AsyncIoStreamWrapper.h"

constexpr int TEST_PORT = 23415;

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
  // kj::Own<kj::PromiseFulfillerPair<bool>> exitPromisePair;
  // const kj::Executor* executor;

  std::array<char, 1024> long_msg;
  randombytes_buf(long_msg.data(), long_msg.size());

  auto server_thread = std::thread(
      [&]{
        auto ioContext = kj::setupAsyncIo();
        auto listen_address =
            ioContext.provider->getNetwork()
            .parseAddress("127.0.0.1", TEST_PORT).wait(ioContext.waitScope);
        auto listener = listen_address->listen();

        auto secure_listener =
            makeEncryptedReceiver<InsecureChannel>(kj::mv(listener));
        auto secure_stream =
            secure_listener.accept().wait(ioContext.waitScope);

        // auto stream = listener->accept().wait(ioContext.waitScope);

        // auto secure_stream =
        //     EncryptedConnection<InsecureChannel<AsyncIoStreamWrapper>>(
        //         kj::mv(stream));

        // FIXME: This breaks. Sometimes tryRead() doesn't write anything to
        //        buffer, so the test fails, printing garbage that was in
        //        the buffer before tryRead() call.
        std::array<char, long_msg.size()> buffer = {0};
        // char buffer[6]; buffer[4] = buffer[5] = '\0';
        // std::this_thread::sleep_for(std::chrono::milliseconds(20));
        // char buffer[5] = {0};
        size_t bytes = secure_stream->tryRead(buffer.data(), 4, 4)
                       .wait(ioContext.waitScope);
        EXPECT_EQ((size_t)4, bytes);
        EXPECT_STREQ("ABCD", buffer.data());

        bytes = secure_stream->tryRead(buffer.data(), 5, 5)
                .wait(ioContext.waitScope);
        EXPECT_EQ((size_t)5, bytes);
        EXPECT_STREQ("EFGHI", buffer.data());

        bytes = secure_stream->tryRead(
            buffer.data(), long_msg.size(), long_msg.size())
                .wait(ioContext.waitScope);
        EXPECT_EQ(long_msg.size(), bytes);
        EXPECT_EQ(long_msg, buffer);
        // executor->executeSync(
            // [&]{ exitPromisePair->fulfiller->fulfill(true); });
      });
  auto client_thread = std::thread(
      [&]{
        auto ioContext = kj::setupAsyncIo();
        // executor = &kj::getCurrentThreadExecutor();
        // exitPromisePair = kj::heap(kj::newPromiseAndFulfiller<bool>());

        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        auto connect_address =
            ioContext.provider->getNetwork()
            .parseAddress("127.0.0.1", TEST_PORT).wait(ioContext.waitScope);
        auto connection = connect_address->connect()
                          .wait(ioContext.waitScope);
        auto secure_connection =
            makeEncryptedConnection<InsecureChannel>(kj::mv(connection));
        secure_connection.connect(); // FIXME: Do it implicitly?

        char buffer[5] = "ABCD";
        secure_connection.write(buffer, 4).wait(ioContext.waitScope);

        secure_connection.write("EFGHI", 5).wait(ioContext.waitScope);

        secure_connection.write(long_msg.data(), long_msg.size())
            .wait(ioContext.waitScope);;

        // exitPromisePair->promise.wait(ioContext.waitScope);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      });

  if (server_thread.joinable()) {
    server_thread.join();
  }
  if (client_thread.joinable()) {
    client_thread.join();
  }
}

// FIXME: This breaks on InsecureChannel::read(), we somehow get nullptr as
//        a buffer to write to. Why?
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
            .parseAddress("127.0.0.1", TEST_PORT).wait(ioContext.waitScope);
        // auto secure_address =
            // makeEncryptedNetworkAddress<InsecureChannel>(
                // kj::mv(listen_address));
        auto listener = listen_address->listen();
        // std::this_thread::sleep_for(std::chrono::milliseconds(20));
        // auto listener = secure_address.listen();
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
            .parseAddress("127.0.0.1", TEST_PORT).wait(ioContext.waitScope);
        // auto secure_address =
            // makeEncryptedNetworkAddress<InsecureChannel>(
                // kj::mv(connect_address));
        auto connection = connect_address->connect()
                          .wait(ioContext.waitScope);
        auto secure_connection =
            EncryptedConnection<InsecureChannel<AsyncIoStreamWrapper>>(
                kj::mv(connection));
        // // auto secure_connection =
        //     // secure_address.connect().wait(ioContext.waitScope);
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


// FIXME: These tests break probably because of AsyncIoStreamWrapper.
//        Look at the fixme in AsyncIoStreamWrapper.h

// NOTE: cap'n'proto expects that the connection handles nullptr buffers
//       gracefully. Probably by returning kj::READY_NOW or 0 as bytes read.
//       It seems to be working with current edition of InsecureChannel.
