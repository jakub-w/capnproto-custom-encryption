#pragma once

#include <system_error>
#include <type_traits>
#include <thread>

#include "tl/expected.hpp"

namespace {
using tl::expected;
using tl::unexpected;
}

// NOTES:
// 1. We're passing the result of internal_stream_.write() and
//    internal_stream_.read() to the caller. It isn't possible to extract any
//    information from it not knowing its type, so 'expected' result type may
//    be unnecessary. It would be only if the internal_stream_'s methods threw
//    errors. They could be caught and turned into std::error_code. Or the
//    resulting error code could be a result of some inner workings of this
//    channel, unrelated to the internal_stream_.
// 2. It would be probably wise to make the class based on that one stateful,
//    contrary to this implementation.
// 3. If internal_stream_.read() or internal_stream_.write() return void
//    the code won't compile because we're assigning their return value to an
//    auto-typed variable.

// These could be used as an alternate way of determining the result of
// write() and read() methods. They'd be used in tandem with internalRead()
// and internalWrite().
// #define WRITE_RESULT(T)                                          \
//   expected<std::invoke_result_t<decltype(&T::internalWrite),    \
//                                 T, void*, size_t>,              \
//            std::error_code>

// #define READ_RESULT(T)                                         \
//   expected<std::invoke_result_t<decltype(&T::internalRead),    \
//                                 T, void*, size_t>,             \
//            std::error_code>

#define INS_CHAN_IO_RESULT expected<decltype(result), std::error_code>

template<class IoStream>
class InsecureChannel {
private:
  IoStream& internal_stream_;

  enum class State {
    DISCONNECTED,
    CONNECTED
  } state = State::DISCONNECTED;

  // inline auto internalRead(void* buffer, size_t size) {
  //   return internal_stream_.read(buffer, size);
  // }
  // inline auto internalWrite(const void* buffer, size_t size) {
  //   return internal_stream_.write(buffer, size);
  // }

 public:
  using writeResult =
      expected<std::invoke_result_t<decltype(&IoStream::write),
                                    IoStream, void*, size_t>,
               std::error_code>;
  using readResult =
      expected<std::invoke_result_t<decltype(&IoStream::read),
                                    IoStream, void*, size_t>,
               std::error_code>;

  InsecureChannel(IoStream& stream)
      : internal_stream_{stream} {}

  [[nodiscard]]
  std::error_code connect() {
    if (State::CONNECTED == state) {
      return std::make_error_code(std::errc::already_connected);
    }

    // Do client's side of a handshake here.

    state = State::CONNECTED;
    return std::error_code{};
  }

  [[nodiscard]]
  std::error_code accept() {
    if (State::CONNECTED == state) {
      return std::make_error_code(std::errc::already_connected);
    }

    // Do server's side of a handshake here.

    state = State::CONNECTED;
    return std::error_code{};
  }

  inline writeResult write(const void* buffer, size_t size) {
    if (State::DISCONNECTED == state) {
      return unexpected{std::make_error_code(std::errc::not_connected)};
    }

    std::cout <<  std::this_thread::get_id() << ": "
              << "writing " << size << " bytes\n";
    try {
      auto result = internal_stream_.write(buffer, size);
      return writeResult{std::move(result)};
    } catch (const std::system_error& e) {
      return writeResult{
        unexpected{e.code()}};
    } catch (const std::exception& e) {
      return writeResult{
        unexpected{std::make_error_code(std::errc::io_error)}};
    }
  }

  inline readResult read(void* buffer, size_t size) {
    if (State::DISCONNECTED == state) {
      return unexpected{std::make_error_code(std::errc::not_connected)};
    }
    std::cout << std::this_thread::get_id() << ": "
              << "reading " << size << " bytes\n";
    try {
      auto result = internal_stream_.read(buffer, size);
      return expected<decltype(result), std::error_code>{std::move(result)};
    } catch (const std::system_error& e) {
      return readResult{
        unexpected{e.code()}};
    } catch (const std::exception& e) {
      return readResult{
        unexpected{std::make_error_code(std::errc::io_error)}};
    }
  }

  // TODO: This should return something like expected<auto, std::error_code>,
  //       where auto would be the result type of internal_stream_.close().
  //       With the current way (look at read()) of doing things, we'd do:
  //       auto result = internal_stream_.close();
  //       It's not possible because the type could be void, as it is in
  //       cap'n'proto's shutdownWrite().
  //       Maybe it would be advisable to force the type and let the
  //       implementor worry about wrapping the function. Return
  //       std::error_code or expected<auto, std::error_code>?
  std::error_code close() {
    if (State::DISCONNECTED == state) {
      return std::make_error_code(std::errc::not_connected);
    }

    std::cout <<  std::this_thread::get_id() << ": "
              << "Closing the connection\n";
    internal_stream_.close();
    return std::error_code{};
  }
};
