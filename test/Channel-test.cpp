#include <gmock/gmock.h>

#include <atomic>
#include <thread>
#include <poll.h>

#include <kj/async-io.h>

#include "../IoStream.h"
#include "../InsecureChannel.h"
#include "../PubkeyChannel.h"
#include "../JpakeChannel.h"

#define err_info { std::string(__FILE__) + ":" + std::to_string(__LINE__) }

class MockIoStream {
  MOCK_METHOD(int, write, (const void* buffer, size_t size));
  MOCK_METHOD(int, read, (void* buffer, size_t size));
  MOCK_METHOD(int, close, ());
};

class PipeIoStream : public IoStream<PipeIoStream> {
  static const auto PREAD = 0;
  static const auto PWRITE = 1;
 public:
  PipeIoStream() {
    int result = pipe(local);
    if (0 != result) {
      throw std::system_error(result, std::system_category(), err_info);
    }
    read_stream = fdopen(local[PREAD], "r");
    if (not read_stream) {
      std::system_error(errno, std::system_category(), err_info);
    }
  }

  PipeIoStream(int fd_write) : PipeIoStream() {
    InstallRemote(fd_write);
  }

  ~PipeIoStream() {
    close();
  }

  void InstallRemote(int fd_write) {
    write_stream = fdopen(fd_write, "w");
    if (not write_stream) {
      std::system_error(errno, std::system_category(), err_info);
    }
  }

  int GetWriteFd() {
    return local[PWRITE];
  }

  int GetReadFd() {
    return local[PREAD];
  }

  expected<size_t, std::error_code> write(const void* buffer, size_t size) {
    if (nullptr == buffer) {
      throw std::system_error(EFAULT, std::system_category(), err_info);
    }
    if (not write_stream) {
      throw std::system_error(ENOTCONN, std::system_category(), err_info);
    }

    size_t result = fwrite(buffer, sizeof(char), size, write_stream);
    if (result == 0) {
      if (feof(write_stream)) {
        close();
        return unexpected{std::make_error_code(std::errc::connection_aborted)};
      }
      if (ferror(write_stream)) {
        if (errno == EPIPE) {
          close();
          return unexpected{std::make_error_code(std::errc::broken_pipe)};
        }
        close();
        return unexpected{std::error_code(errno, std::system_category())};
      }
    }
    if (fflush(write_stream) != 0) {
      close();
      if (errno == EPIPE) {
        return unexpected{std::make_error_code(std::errc::broken_pipe)};
      }
      return unexpected{std::error_code(errno, std::system_category())};
    }
    return result;
  }

  expected<size_t, std::error_code> read(void* buffer, size_t size) {
    if (nullptr == buffer) {
      throw std::system_error(EFAULT, std::system_category(), err_info);
    }

    int result = fread(buffer, sizeof(char), size, read_stream);
    if (result == 0) {
      if (feof(read_stream)) {
        close();
        return unexpected{std::make_error_code(std::errc::connection_aborted)};
      }
      if (ferror(read_stream)) {
        if (errno == EPIPE) {
          close();
          return unexpected{std::make_error_code(std::errc::broken_pipe)};
        }
        close();
        return unexpected{std::error_code(errno, std::system_category())};
      }
    }

    return result;
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

template <class IoStream>
class JpakeChannelTestWrapper {
  JpakeChannel<IoStream> channel;

  static uint count;

 public:
  JpakeChannelTestWrapper(IoStream& stream) : channel{stream} {}

  auto connect() {
    std::error_code ec = channel.initialize(
        "password", "id-" + std::to_string(count++));
    if (ec) return ec;
    return channel.connect();
  }
  auto accept() {
    std::error_code ec = channel.initialize(
        "password", "id-" + std::to_string(count++));
    if (ec) return ec;
    return channel.accept();
  }
  inline auto write(const void* buffer, size_t size) {
    return channel.write(buffer, size);
  }
  inline auto read(void* buffer, size_t size) {
    return channel.read(buffer, size);
  }
  inline auto close() { return channel.close(); }
};
template <class IoStream>
uint JpakeChannelTestWrapper<IoStream>::count = 1;

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
          std::error_code ec = server_channel.accept();
          if (not no_accept && ec) {
            std::cerr << "Accept didn't succeed. Error: " << ec.message()
                      << '\n';
            return;
          }

          std::string alphabet{"ABCDEFGHIJKLMNOPQRSTUVWXYZ"};
          std::string out_buf{' ', 10};

          pollfd fds[2];
          int timeout_msecs = 500;

          fds[0].fd = server_stream.GetReadFd();
          fds[0].events = POLLIN | POLLHUP | POLLERR;
          fds[1].fd = server_stream.GetWriteFd();
          fds[1].events = POLLOUT | POLLHUP | POLLERR;

          bool written = false;
          while (run) {
            int ret = poll(fds, 2, timeout_msecs);
            if (-1 == ret) {
              if (EAGAIN == errno) continue;
              perror("Error in poll");
              throw std::system_error(
                  errno, std::system_category(), err_info);
            }

            for (int i = 0; i < 2; ++i) {
              if ((fds[i].revents & POLLOUT) && not written) {
                try {
                  server_channel.write(alphabet.c_str(), 10);
                  written = true;
                } catch (const std::system_error& e) {
                  if (e.code() != std::errc::not_connected)
                    std::cerr << e.what() << '\n';
                }
              }
              if (fds[i].revents & POLLIN) {
                try {
                server_channel.read(out_buf.data(), 10);
                } catch (const std::system_error& e) {
                  if (e.code() != std::errc::not_connected)
                    std::cerr << e.what() << '\n';
                }
              }
              if (fds[i].revents & POLLHUP) {
                break;
              }
              if (fds[i].revents & POLLERR) {
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

  void NoAccept() {
    no_accept = true;
  }

  T& channel;

 private:
  PipeIoStream server_stream;
  PipeIoStream client_stream;
  T server_channel;
  T client_channel;

  std::thread server_thread;
  std::atomic_bool run = true;

  bool no_accept = false;
};

// FIXME: Fix death tests. They're disabled because of threads.
template <typename T>
using DISABLED_ChannelDeathTest = ChannelTest<T>;

using writeResult = expected<size_t, std::error_code>;
using readResult = expected<size_t, std::error_code>;

using TestTypes = ::testing::Types<InsecureChannel<PipeIoStream>,
                                   PubkeyChannel<PipeIoStream>,
                                   JpakeChannelTestWrapper<PipeIoStream>
                                   >;
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
  ASSERT_FALSE(ec)
      << "Connecting to the channel failed.\n"
      "ec.message() == " << ec.message();

  ec = channel.connect();
  EXPECT_TRUE(ec)
      << "Calling connect() on already connected channel should return an "
      "error";
  EXPECT_EQ(ec.value(), (int)std::errc::already_connected)
      << "ec.message() == " << ec.message();
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
  TestFixture::NoAccept();
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
  TestFixture::NoAccept();
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
  ASSERT_TRUE(result.has_value())
      << "Contains an error instead: " << result.error().message() << '\n';
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
// IMPORTANT
//       They probably should return expected<size_t, error_code> because
//       the stream could return an error.
//       Not handling network errors could lead to a hanging, broken
//       connection. Probable security issue? DOS perhaps.

// ! PRIORITY
// TODO: IoStream should be required to signal errors somehow from write() and
//       read(). We don't want to have a SIGPIPE, we want to handle the stream
//       closing.
// IDEA: Make Channels to assume nothing throws and create a base class for
//       IoStreams. They will be the ones to worry about interfacing with
//       external implementations.
// For EncryptedConnection class to work the promises returned from writing
// and reading should be passed through the Channel class, so the tight
// cooperation with cap'n'proto is pretty much impossible for encrypted
// streams that must check the length of the messages. The bufferred stream
// should be implemented instead of AsyncIoStreamWrapper, just like in the
// default TLS implementation (invoking the promises before returning control
// to the Channel). Then the EncryptedConnection would have to create new
// promises to return. OMG what a PITA.
// But that means my IoStream class can stay and be useful. But all these
// layers of indirection...

// TODO: Catch errors from internal_stream_ in connect() and accept() too.
//       Make a test for checking that.
