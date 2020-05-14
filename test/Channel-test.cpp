#include <gmock/gmock.h>

#include <kj/async-io.h>

#include "../InsecureChannel.h"
#include "../PubkeyChannel.h"

class MockIoStream {
  MOCK_METHOD(int, write, (const void* buffer, size_t size));
  MOCK_METHOD(int, read, (void* buffer, size_t size));
  MOCK_METHOD(int, close, ());
};

class FakeIoStream {
 public:
  std::string write(const void* buffer, size_t size) {
    if (nullptr == buffer) {
      throw std::system_error(EFAULT, std::system_category());
    }
    return std::string{static_cast<const char*>(buffer), size};
  }
  int read(void* buffer, size_t size) {
    if (nullptr == buffer) {
      throw std::system_error(EFAULT, std::system_category());
    }
    int count = std::min(alphabet.size(), size);
    memcpy(buffer, alphabet.data(), count);
    return count;
  }
  int close() {
    return 0;
  }

 private:
  const std::string alphabet{"ABCDEFGHIJKLMNOPQRSTUVWXYZ"};
};

template <typename T>
class ChannelTest : public ::testing::Test {
 protected:
  ChannelTest() : ::testing::Test(), stream{}, channel{stream} {}

  // MockIoStream stream;
  FakeIoStream stream;
  T channel;
};

using writeResult = expected<std::string, std::error_code>;
using readResult = expected<int, std::error_code>;

using TestTypes = ::testing::Types<InsecureChannel<FakeIoStream>,
                                   PubkeyChannel<FakeIoStream> >;
TYPED_TEST_SUITE(ChannelTest, TestTypes);

TYPED_TEST(ChannelTest, connect) {
  TypeParam& channel = TestFixture::channel;

  // TODO: test if connecting the channel that has faulty/disconnected
  //       internal stream returns errors.
  std::error_code ec = channel.connect();
  EXPECT_FALSE(ec);

  ec = channel.connect();
  EXPECT_TRUE(ec)
      << "Calling connect() on already connected channel should return an "
      "error";
  EXPECT_EQ(ec.value(), (int)std::errc::already_connected);
}

TYPED_TEST(ChannelTest, accept) {
  TypeParam& channel = TestFixture::channel;

  // TODO: test if accepting on the channel that has faulty/disconnected
  //       internal stream returns errors.
  std::error_code ec = channel.accept();
  EXPECT_FALSE(ec);

  ec = channel.accept();
  EXPECT_TRUE(ec)
      << "Calling accept() on already connected channel should return an "
      "error";
  EXPECT_EQ(ec.value(), (int)std::errc::already_connected);
}

TYPED_TEST(ChannelTest, write) {
  TypeParam& channel = TestFixture::channel;
  writeResult result;

  EXPECT_NO_THROW(result = channel.write("foo", 3))
      << "Channel shouldn't throw on write when not connected. It should "
      "return an error_code";
  EXPECT_FALSE(result.has_value())
      << "Not connected channel should return an error";
  EXPECT_EQ(result.error().value(), ENOTCONN);

  channel.connect();

  EXPECT_NO_THROW(result = channel.write(nullptr, 10))
      << "Channel should catch any throw and return std::error_code in "
      "'expected' object instead";
  EXPECT_FALSE(result.has_value()) << "Should have an error instead";
  EXPECT_EQ(result.error().value(), EFAULT);

  const std::string message{"Test"};
  result = channel.write(message.c_str(), message.size());
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result.value(), message);
}

TYPED_TEST(ChannelTest, read) {
  TypeParam& channel = TestFixture::channel;
  readResult result;
  std::string message(10, ' ');

  EXPECT_NO_THROW(result = channel.read(message.data(), message.size()))
      << "Channel shouldn't throw on read when not connected. It should "
      "return an error_code";
  EXPECT_FALSE(result.has_value())
      << "Not connected channel should return an error";
  EXPECT_EQ(result.error().value(), ENOTCONN);
  EXPECT_EQ(std::string(10, ' '), message);

  channel.connect();

  EXPECT_NO_THROW(result = channel.read(nullptr, 10))
      << "Channel should catch any throw and return std::error_code in "
      "'expected' object instead";
  EXPECT_FALSE(result.has_value()) << "Should have an error instead";
  EXPECT_EQ(result.error().value(), EFAULT);

  result = channel.read(message.data(), message.size());
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ((size_t)result.value(), message.size());
  EXPECT_EQ(message, "ABCDEFGHIJ");
}

TYPED_TEST(ChannelTest, close) {
  TypeParam& channel = TestFixture::channel;

  std::error_code ec = channel.close();
  EXPECT_TRUE(ec)
      << "Not connected channel should return an error on close()";

  channel.connect();

  ec = channel.close();
  EXPECT_FALSE(ec);

  // TODO: Make it possible to test if throwing from close is stopped by the
  //       channel.
}

// TODO: Implement BufferIoStream that will write and read from a simple
//       buffer. This will be sufficient to test server-client stuff.
// TODO: Implement server-client tests because anything else than
//       InsecureStream will fail every test.
// TODO: A Channel who's internal stream isn't connected should return error
//       errors on connect(), read() and write().
// TODO: If connect() or accept() returns errc::resource_unavailable_try_again
//       (EAGAIN), loop and try again until different error occurs or no error
//       at all.
// NOTE: Preferably I'd want for channels to work with -fno-exceptions and
//       -fno-rtti. Should I require channels to catch exceptions then?
//       One solution would be to enable error catching depending on if
//       they're enabled or not (with #ifdefs). Other libraries do it.
// NOTE: Maybe it should be the EncryptedConnection that checks if buffers are
//       valid pointers? Should every channel check it if they are used only
//       inside EncryptedConnection? This smells like a lot of code
//       duplication. Maybe Channels should just assert that buffers are not
//       nullptr. Failed assertions can be checked with EXPECT_DEBUG_DEATH().
//       Ok, I forgot that EncryptedConnection is an adaptor and not the part
//       of the library proper, so I guess channels should check if the buffer
//       is null after all.
//       The question is if they should assert or return error codes? Maybe
//       both? We don't like hard crashes.
// FIXME: PubkeyChannel segfaults on write() test. Probably because it
//        writes more than the given size.
