#include <gmock/gmock.h>

#include <atomic>
#include <thread>
#include <poll.h>

#include <kj/async-io.h>

#include "../InsecureChannel.h"
#include "../PubkeyChannel.h"

class MockIoStream {
  MOCK_METHOD(int, write, (const void* buffer, size_t size));
  MOCK_METHOD(int, read, (void* buffer, size_t size));
  MOCK_METHOD(int, close, ());
};

class PipeIoStream {
  static const auto PREAD = 0;
  static const auto PWRITE = 1;
 public:
  PipeIoStream() {
    int result = pipe(local);
    if (0 != result) {
      throw std::system_error(result, std::system_category());
    }
    read_stream = fdopen(local[PREAD], "r");
  }

  PipeIoStream(int fd_write) : PipeIoStream() {
    InstallRemote(fd_write);
  }

  ~PipeIoStream() {
    close();
  }

  void InstallRemote(int fd_write) {
    write_stream = fdopen(fd_write, "w");
  }

  int GetWriteFd() {
    return local[PWRITE];
  }

  int GetReadFd() {
    return local[PREAD];
  }

  size_t write(const void* buffer, size_t size) {
    if (nullptr == buffer) {
      throw std::system_error(EFAULT, std::system_category());
    }
    if (not write_stream) {
      throw std::system_error(ENOTCONN, std::system_category());
    }

    size_t result = fwrite(buffer, sizeof(char), size, write_stream);
    fflush(write_stream);
    return result;
  }

  size_t read(void* buffer, size_t size) {
    if (nullptr == buffer) {
      throw std::system_error(EFAULT, std::system_category());
    }

    return fread(buffer, sizeof(char), size, read_stream);
  }

  int close() {
    if (read_stream) {
      fclose(read_stream);
      read_stream = nullptr;
    }

    if (write_stream) {
      fclose(write_stream);
      write_stream = nullptr;
    }

    return 0;
  }

 private:
  int local[2];
  FILE* write_stream = nullptr;
  FILE* read_stream = nullptr;
};

TEST(PipeIoStream, Test) {
  PipeIoStream server;
  PipeIoStream client(server.GetWriteFd());
  server.InstallRemote(client.GetWriteFd());

  std::thread server_thread{
    [&server]{
      char buffer[10];
      server.read(buffer, 4);
      EXPECT_STREQ(buffer, "foo");
    }};

  std::thread client_thread{
    [&client]{
      const char buffer[10] = "foo";
      client.write(buffer, 4);
    }};

  if (server_thread.joinable()) server_thread.join();
  if (client_thread.joinable()) client_thread.join();
}

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
  ChannelTest() : ::testing::Test(),
    channel{client_channel},
    server_stream{},
    client_stream{server_stream.GetWriteFd()},
    server_channel{server_stream},
    client_channel{client_stream} {
      server_stream.InstallRemote(client_stream.GetWriteFd());
  }

  void SetUp() {
    server_thread = std::thread(
        [this]{
          server_channel.accept();

          std::string alphabet{"ABCDEFGHIJKLMNOPQRSTUVWXYZ"};
          std::string out_buf{' ', 10};

          pollfd fds[2];
          int timeout_msecs = 500;

          fds[0].fd = server_stream.GetReadFd();
          fds[0].events = POLLIN;
          fds[1].fd = server_stream.GetWriteFd();
          fds[1].events = POLLOUT;

          while (run) {
            int ret = poll(fds, 2, timeout_msecs);
            if (-1 == ret) {
              if (EAGAIN == errno) continue;
              throw std::system_error(errno, std::system_category());
            }

            for (int i = 0; i < 2; ++i) {
              if (fds[i].revents & POLLOUT) {
                server_channel.write(alphabet.c_str(), 10);
              }
              if (fds[i].revents & POLLIN) {
                server_channel.read(out_buf.data(), 10);
              }
              if (fds[i].revents & POLLHUP) {
                break;
              }
            }
          }
        });
  }

  void TearDown() {
    run = false;
    client_stream.close();
    if (server_thread.joinable()) {
      server_thread.join();
    }
  }

  // FakeIoStream stream;

  T& channel;

 private:
  PipeIoStream server_stream;
  PipeIoStream client_stream;
  T server_channel;
  T client_channel;

  std::thread server_thread;
  std::atomic_bool run = true;
};

// FIXME: Fix death tests. They're disabled because of threads.
template <typename T>
using DISABLED_ChannelDeathTest = ChannelTest<T>;

using writeResult = expected<size_t, std::error_code>;
using readResult = expected<size_t, std::error_code>;

using TestTypes = ::testing::Types<InsecureChannel<PipeIoStream>,
                                   PubkeyChannel<PipeIoStream> >;
// using DeathTestTypes = ::testing::Types<InsecureChannel<FakeIoStream>,
//                                         PubkeyChannel<FakeIoStream> >;
TYPED_TEST_SUITE(ChannelTest, TestTypes);
TYPED_TEST_SUITE(DISABLED_ChannelDeathTest, TestTypes);

// accept() runs automatically from the test suite.
TYPED_TEST(ChannelTest, connect_accept) {
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

// Disabled because it's implied in the connect() test.
TYPED_TEST(ChannelTest, DISABLED_accept) {
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

TYPED_TEST(ChannelTest, writeBeforeConnecting) {
  TypeParam& channel = TestFixture::channel;
  writeResult result;

  EXPECT_NO_THROW(result = channel.write("foo", 3))
      << "Channel shouldn't throw on write when not connected. It should "
      "return an error_code";
  EXPECT_FALSE(result.has_value())
      << "Not connected channel should return an error";
  EXPECT_EQ(result.error().value(), ENOTCONN);

#ifdef DNDEBUG
  EXPECT_NO_THROW(result = channel.write(nullptr, 10))
      << "Channel should catch any throw and return std::error_code in "
      "'expected' object instead";
  EXPECT_FALSE(result.has_value()) << "Should have an error instead";
  EXPECT_EQ(result.error().value(), EFAULT);
#endif
}

TYPED_TEST(ChannelTest, write) {
  TypeParam& channel = TestFixture::channel;
  writeResult result;

  channel.connect();

#ifdef DNDEBUG
  EXPECT_NO_THROW(result = channel.write(nullptr, 10))
      << "Channel should catch any throw and return std::error_code in "
      "'expected' object instead";
  EXPECT_FALSE(result.has_value()) << "Should have an error instead";
  EXPECT_EQ(result.error().value(), EFAULT);
#endif

  const std::string message{"Test"};
  result = channel.write(message.c_str(), message.size());
  ASSERT_TRUE(result.has_value());
  // FIXME: Check if the server received the message
  // EXPECT_EQ(result.value(), message);
  EXPECT_EQ(result.value(), message.size());
}

TYPED_TEST(DISABLED_ChannelDeathTest, write) {
  TypeParam& channel = TestFixture::channel;

  EXPECT_DEBUG_DEATH(channel.write(nullptr, 10), "Assertion.*failed")
      << "Should fail an assert even before connecting";

  channel.connect();

  EXPECT_DEBUG_DEATH(channel.write(nullptr, 10), "Assertion.*failed")
      << "Should fail an assert after connecting";
}

TYPED_TEST(ChannelTest, readBeforeConnecting) {
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

#ifdef DNDEBUG
  EXPECT_NO_THROW(result = channel.read(nullptr, 10))
      << "Channel should catch any throw and return std::error_code in "
      "'expected' object instead.";
  EXPECT_FALSE(result.has_value())
      << "Should return an error when trying to read from nullptr";
  EXPECT_EQ(result.error().value(), EFAULT)
      << "Reading from nullptr should return std::errc::bad_address";
#endif
}

TYPED_TEST(ChannelTest, read) {
  TypeParam& channel = TestFixture::channel;
  readResult result;
  std::string message(10, ' ');

  channel.connect();

#ifdef DNDEBUG
  EXPECT_NO_THROW(result = channel.read(nullptr, 10))
      << "Channel should catch any throw and return std::error_code in "
      "'expected' object instead";
  EXPECT_FALSE(result.has_value())
      << "Should return an error when trying to read from nullptr";
  EXPECT_EQ(result.error().value(), EFAULT)
      << "Reading from nullptr should return std::errc::bad_address";
#endif

  result = channel.read(message.data(), message.size());
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ((size_t)result.value(), message.size());
  EXPECT_EQ(message, "ABCDEFGHIJ");
}

TYPED_TEST(DISABLED_ChannelDeathTest, read) {
  TypeParam& channel = TestFixture::channel;
  readResult result;

  EXPECT_DEBUG_DEATH(channel.read(nullptr, 10), "Assertion.*failed")
      << "Should fail an assert even before connecting";

  channel.connect();

  EXPECT_DEBUG_DEATH(channel.read(nullptr, 10), "Assertion.*failed")
      << "Should fail an assert after connecting";
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

// TODO: Make IoStream.write() return size_t of the bytes written, likewise
//       for read(). For encryption it's crucial to know the size of the
//       received message.
//       The internal stream could be required to return size_t or
//       pair<auto, size_t>.
