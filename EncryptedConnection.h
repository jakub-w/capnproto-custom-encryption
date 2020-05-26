#pragma once
#include <arpa/inet.h>

#include <system_error>

#include <kj/async-io.h>
#include <kj/debug.h>

#include "tl/expected.hpp"

#include "InsecureChannel.h"
#include "AsyncIoStreamWrapper.h"

/// \e EncryptedConnection never copies or moves \e Channel object so it
/// should be safe not to create explicit copy and move constructors for
/// \e Channel implementations. This may change in the future.
/// Channel should stop any throw from its internal IoStream and return
/// error_code instead.
///
/// Channel should \verbatim assert(buffer != nullptr) \endverbatim as a first
/// instruction in \e write() and \e read() function.
/// In the non-debug (\e NDEBUG) builds it should check if the buffer pointer
/// is null and return an error instead: \e std::errc::bad_address
/// (\e EFAULT) system error code.
///
/// It's crucial to call \ref connect() or \ref accept() after wrapping the
/// \e AsyncIoStream. This will do a handshake that is needed for encryption.
/// The server should call \ref accept(), while the client should call
/// \ref connect().
template<typename Channel>
class EncryptedConnection : public kj::AsyncIoStream {
 public:
  EncryptedConnection(kj::Own<kj::AsyncIoStream> stream)
      : internal_stream_{kj::mv(stream)},
        stream_wrapper_{
          kj::heap<AsyncIoStreamWrapper>(internal_stream_.get())},
        channel_{kj::heap<Channel>(*stream_wrapper_)} {}

  EncryptedConnection(EncryptedConnection&& other)
      : internal_stream_{kj::mv(other.internal_stream_)},
        stream_wrapper_{kj::mv(other.stream_wrapper_)},
        channel_{kj::mv(other.channel_)} {}

  virtual ~EncryptedConnection() {}

  EncryptedConnection() = delete;
  EncryptedConnection(const EncryptedConnection&) = delete;
  EncryptedConnection operator=(EncryptedConnection) = delete;
  EncryptedConnection operator=(EncryptedConnection&&) = delete;
  EncryptedConnection operator=(const EncryptedConnection&) = delete;

  [[nodiscard]]
  std::error_code connect() {
    return channel_->connect();
  }

  [[nodiscard]]
  std::error_code accept() {
    return channel_->accept();
  }

  kj::Promise<size_t> tryRead(void* buffer,
                              size_t /* minBytes */,
                              size_t maxBytes) final {
    auto result = channel_->read(buffer, maxBytes);
    if (result.has_value()) {
      return std::move(result.value());
    } else {
      // NOTE: Look at TODO note at the bottom of the file.
      // KJ_FAIL_ASSERT("Error while writing to encrypted channel: ",
      //                result.error().message());
      return size_t{0};
    }
  }

  kj::Promise<void> write(const void* buffer, size_t size) final {
    return writeInternal(
        kj::arrayPtr(reinterpret_cast<const kj::byte*>(buffer), size),
        nullptr);
  }

  kj::Promise<void> write(
      kj::ArrayPtr<const kj::ArrayPtr<const kj::byte>> pieces) final {
    return writeInternal(pieces[0], pieces.slice(1, pieces.size()));
  }

  kj::Promise<void> whenWriteDisconnected() final {
    return internal_stream_->whenWriteDisconnected();
  }

  void abortRead() final {
    internal_stream_->abortRead();
  }

  void shutdownWrite() final {
     // KJ_REQUIRE(shutdownTask == nullptr, "already called shutdownWrite()");
    channel_->close();
  }

 private:
  kj::Promise<void> writeInternal(
      kj::ArrayPtr<const kj::byte> first,
      kj::ArrayPtr<const kj::ArrayPtr<const kj::byte>> rest) {
    // KJ_REQUIRE(shutdownTask == nullptr, "already called shutdownWrite()");

    // omit zero-sized writes
    while (first.size() == 0) {
      if (rest.size() == 0) {
        return kj::READY_NOW;
      }
      first = rest.front();
      rest = rest.slice(1, rest.size());
    }

    expected<kj::Promise<void>, std::error_code> result =
        channel_->write(first.begin(), first.size());

    if (result.has_value()) {
      return result.value().then(
          [this, rest]() -> kj::Promise<void> {
            if (rest.size() > 0) {
              return writeInternal(rest[0], rest.slice(1, rest.size()));
            } else {
              return kj::READY_NOW;
            }
          });
    } else {
      // NOTE: Look at a TODO note at the bottom of the file.
      // KJ_FAIL_ASSERT("Encrypted connection error: ",
      //                result.error().message());
      return kj::READY_NOW;
    }
  }

 protected:
  kj::Own<kj::AsyncIoStream> internal_stream_;
  kj::Own<AsyncIoStreamWrapper> stream_wrapper_;
  kj::Own<Channel> channel_;
};

template<typename Channel>
class EncryptedConnectionReceiver final : public kj::ConnectionReceiver {
  kj::Own<kj::ConnectionReceiver> internal_receiver_;

 public:
  EncryptedConnectionReceiver(kj::Own<kj::ConnectionReceiver> receiver)
      : internal_receiver_{kj::mv(receiver)} {}

  EncryptedConnectionReceiver(EncryptedConnectionReceiver&& other)
      : internal_receiver_{kj::mv(other.internal_receiver_)} {}

  EncryptedConnectionReceiver() = delete;
  EncryptedConnectionReceiver(const EncryptedConnectionReceiver&) = delete;
  EncryptedConnectionReceiver operator=(
      EncryptedConnectionReceiver&&) = delete;
  EncryptedConnectionReceiver operator=(
      const EncryptedConnectionReceiver&) = delete;

  kj::Promise<kj::Own<kj::AsyncIoStream>> accept() final {
    return internal_receiver_->accept().then(
        [](kj::Own<kj::AsyncIoStream> stream)
        -> kj::Promise<kj::Own<kj::AsyncIoStream>> {
          auto connection = kj::heap<EncryptedConnection<Channel>>(
              kj::mv(stream));

          std::error_code ec = connection->accept();
          // FIXME: This should probably be connection->close() with an
          //        argument that specifies why it closed.
          if (ec) connection->shutdownWrite();
          if (ec) std::cerr << "Error: " << ec.message() << '\n';

          return kj::Promise<kj::Own<kj::AsyncIoStream>>(kj::mv(connection));
        });
  }

  void getsockopt(int level, int option, void* value, uint* length) final {
    return internal_receiver_->getsockopt(level, option, value, length);
  }

  void setsockopt(int level, int option,
                  const void* value, uint length) final {
    return internal_receiver_->setsockopt(level, option, value, length);
  }

  uint getPort() final {
    return internal_receiver_->getPort();
  }
};

template<typename Channel>
class EncryptedNetworkAddress final : public kj::NetworkAddress {
  kj::Own<NetworkAddress> internal_address_;

 public:
  EncryptedNetworkAddress(kj::Own<kj::NetworkAddress> address)
      : internal_address_{kj::mv(address)} {}

  EncryptedNetworkAddress(EncryptedNetworkAddress&& other)
      : internal_address_{kj::mv(other.internal_address_)} {}

  EncryptedNetworkAddress() = delete;
  EncryptedNetworkAddress(const EncryptedNetworkAddress&) = delete;
  EncryptedNetworkAddress operator=(EncryptedNetworkAddress) = delete;
  EncryptedNetworkAddress operator=(EncryptedNetworkAddress&&) = delete;
  EncryptedNetworkAddress operator=(const EncryptedNetworkAddress&) = delete;

  kj::Promise<kj::Own<kj::AsyncIoStream>> connect() final {
    return internal_address_->connect().then(
        [](kj::Own<kj::AsyncIoStream> stream) -> kj::Own<kj::AsyncIoStream>{
          return kj::heap<EncryptedConnection<Channel>>(kj::mv(stream));
        });
  }

  inline kj::Own<kj::ConnectionReceiver> listen() final {
    return kj::heap<EncryptedConnectionReceiver<Channel>>(
        internal_address_->listen());
  }

  inline kj::Own<kj::DatagramPort> bindDatagramPort() final {
    return internal_address_->bindDatagramPort();
  }

  kj::Own<kj::NetworkAddress> clone() final {
    KJ_UNIMPLEMENTED("Can't clone the EncryptedNetworkAddress");
  }

  inline kj::String toString() final {
    return internal_address_->toString();
  }
};


/// Use like this:
/// \code{.cpp}
/// makeEncryptedConnection<PubkeyChannel>(kj::mv(stream));
/// \endcode
template<template<class> class Channel>
inline EncryptedConnection<Channel<AsyncIoStreamWrapper>>
makeEncryptedConnection(kj::Own<kj::AsyncIoStream> stream) {
  return EncryptedConnection<Channel<AsyncIoStreamWrapper>>(kj::mv(stream));
}

/// Use like this:
/// \code{.cpp}
/// makeEncryptedReceiver<PubkeyChannel>(kj::mv(receiver));
/// \endcode
template<template<class> class Channel>
inline EncryptedConnectionReceiver<Channel<AsyncIoStreamWrapper>>
makeEncryptedReceiver(kj::Own<kj::ConnectionReceiver> receiver) {
  return EncryptedConnectionReceiver<Channel<AsyncIoStreamWrapper>>(
      kj::mv(receiver));
}

// TODO: EncryptedConnection should store the reason of the disconnection so
//       it could be read by the user.
// TODO: Design decision: Call KJ_FAIL_ASSERT on errors returned by the
//       Channel or make custom facility for handling errors, without RTTI?
//       Like an error callback. Or maybe reuse capnproto's error callback
//       functionality that is used when RTTI is disabled?
//       NOTE: Adjust tests to reflect that!
