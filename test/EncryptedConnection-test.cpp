#include <gmock/gmock.h>

#include "../EncryptedConnection.h"

class FakeAsyncIoStream final : public kj::AsyncIoStream {
 public:
  kj::Promise<size_t> tryRead(void*, size_t, size_t maxBytes) final {
    return kj::Promise<size_t>(maxBytes);
  }
  kj::Promise<void> write(const void*, size_t) final {
    return kj::READY_NOW;
  }
  kj::Promise<void> write(
      kj::ArrayPtr<const kj::ArrayPtr<const kj::byte>>) final {
    return kj::READY_NOW;
  }
  kj::Promise<void> whenWriteDisconnected() final {
    return kj::READY_NOW;
  }

  void abortRead() final {}

  void shutdownWrite() final {}

};

class MockChannel {
 public:
  using writeResult = tl::expected<kj::Promise<void>, std::error_code>;
  using readResult = tl::expected<kj::Promise<size_t>, std::error_code>;

  MockChannel (AsyncIoStreamWrapper&) {}

  MOCK_METHOD(std::error_code, connect, ());
  MOCK_METHOD(std::error_code, accept, ());
  MOCK_METHOD(std::error_code, close, ());
  MOCK_METHOD(writeResult, write, (const void* buffer, size_t size));
  MOCK_METHOD(readResult, read, (void* buffer, size_t size));
};

// For exposing the private channel;
class EncryptedConnectionWrapper : public EncryptedConnection<MockChannel> {
 public:
  EncryptedConnectionWrapper(kj::Own<FakeAsyncIoStream> stream)
      : EncryptedConnection<MockChannel>(kj::mv(stream)) {}

  MockChannel& GetChannel() { return *channel_; }
};

class EncryptedConnectionTest : public testing::Test {
 public:
  EncryptedConnectionTest()
      : connection{kj::heap(FakeAsyncIoStream{})},
        channel{connection.GetChannel()} {}

  virtual ~EncryptedConnectionTest() noexcept {}

 protected:
  EncryptedConnectionWrapper connection;
  MockChannel& channel;
  kj::AsyncIoContext ctx = kj::setupAsyncIo();
  char buffer[1];
};

using ::testing::_;

TEST_F(EncryptedConnectionTest, connect) {
  // TODO: Check if EncryptedConnection::connect() returns the same value
  //       the internal channel does.
  EXPECT_CALL(channel, connect()).Times(testing::Exactly(1));
  connection.connect();
}

TEST_F(EncryptedConnectionTest, accept) {
  // TODO: Check if EncryptedConnection::connect() returns the same value
  //       the internal channel does.
  EXPECT_CALL(channel, accept()).Times(testing::Exactly(1));
  connection.accept();
}

TEST_F(EncryptedConnectionTest, shutdownWrite) {
  EXPECT_CALL(channel, close())
      .Times(testing::Exactly((1)));
  connection.shutdownWrite();
}

TEST_F(EncryptedConnectionTest, tryRead) {
  EXPECT_CALL(channel, read(_, 10))
      .Times(testing::Exactly(1))
      .WillOnce(testing::Return(testing::ByMove(
          MockChannel::readResult(tl::in_place, (size_t) 10))));

  size_t result = connection.read(buffer, 0, 10).wait(ctx.waitScope);
  EXPECT_EQ((size_t)10, result) << "Correct read should return non-zero bytes";

  // Test if returning an error code from the channel will result in tryRead
  // returning 0.
  EXPECT_CALL(channel, read(_, 10))
      .Times(testing::Exactly(1))
      .WillOnce(testing::Return(testing::ByMove(
          MockChannel::readResult(
              tl::unexpect, std::make_error_code(std::errc::bad_address)))));

  result = connection.read(nullptr, 0, 10).wait(ctx.waitScope);
  EXPECT_EQ((size_t)0, result)
      << "Read from channel that returns an error code should result in a"
      " return value of 0";
}

TEST_F(EncryptedConnectionTest, write) {
  EXPECT_CALL(channel, write(_, 10))
      .Times(testing::Exactly(1))
      .WillOnce(testing::Return(testing::ByMove(
          MockChannel::writeResult(tl::in_place, kj::READY_NOW))));

  connection.write(buffer, 10);

  // TODO: Test the second overload of EncryptedConnection::write()
}
