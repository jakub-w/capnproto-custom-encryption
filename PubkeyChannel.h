#pragma once

#include <cassert>
#include <system_error>
#include <variant>

#include "tl/expected.hpp"
#include "sodium.h"

namespace {
using tl::expected;
using tl::unexpected;

template<class... Ts> struct overload : Ts... { using Ts::operator()...; };
template<class... Ts> overload(Ts...) -> overload<Ts...>;
}

// This channel is vulnerable to MiTM attacks and is not very secure.
// It's more of a reference implementation.
template<class IoStream>
class PubkeyChannel {
  using WriteResult =
      expected<std::invoke_result_t<decltype(&IoStream::write),
                                    IoStream, void*, size_t>,
               std::error_code>;
  using ReadResult =
      expected<std::invoke_result_t<decltype(&IoStream::read),
                                    IoStream, void*, size_t>,
               std::error_code>;

  struct disconnected {};
  struct connecting {};
  struct connected {
    unsigned char publickey[crypto_box_PUBLICKEYBYTES];
    unsigned char secretkey[crypto_box_SECRETKEYBYTES];

    unsigned char peer_publickey[crypto_box_PUBLICKEYBYTES];
  };
  struct disconnecting {};

  using State =
      std::variant<disconnected, connecting, connected, disconnecting>;

  // PRIVATE FIELDS
  State state_ = disconnected{};
  IoStream& internal_stream_;

  // PRIVATE METHODS
  static inline std::error_code not_connected_ec() {
    return std::make_error_code(std::errc::not_connected);
  }
  static inline std::error_code already_connected_ec() {
    return std::make_error_code(std::errc::already_connected);
  }
  static inline std::error_code connection_pending_ec() {
    return std::make_error_code(std::errc::connection_already_in_progress);
  }
  static inline std::error_code try_again_ec() {
    return std::make_error_code(std::errc::resource_unavailable_try_again);
  }
  static inline std::error_code bad_message_ec() {
    return std::make_error_code(std::errc::bad_message);
  }
  static inline std::error_code protocol_error_ec() {
    return std::make_error_code(std::errc::protocol_error);
  }

 public:
  PubkeyChannel(IoStream& stream) : internal_stream_{stream} {}

  std::error_code connect() {
    return std::visit(
        overload{
          [this](disconnected&){
            state_ = connecting{};

            connected context;
            crypto_box_keypair(context.publickey, context.secretkey);

            internal_stream_.write(context.publickey,
                                   crypto_box_PUBLICKEYBYTES);
            internal_stream_.read(context.peer_publickey,
                                  crypto_box_PUBLICKEYBYTES);

            state_ = context;
            return std::error_code{};
          },
          [](connecting&){ return connection_pending_ec(); },
          [](connected&){ return already_connected_ec(); },
          [](disconnecting&){ return try_again_ec(); }
        },
        state_);
  }

  std::error_code accept() {
    return std::visit(
        overload{
          [this](disconnected&){
            state_ = connecting{};

            connected context;
            crypto_box_keypair(context.publickey, context.secretkey);

            internal_stream_.read(context.peer_publickey,
                                  crypto_box_PUBLICKEYBYTES);
            internal_stream_.write(context.publickey,
                                   crypto_box_PUBLICKEYBYTES);

            state_ = context;
            return std::error_code{};
          },
          [](connecting&){ return connection_pending_ec(); },
          [](connected&){ return already_connected_ec(); },
          [](disconnecting&){ return try_again_ec(); }
        },
        state_);
  }

  WriteResult write(const void* buffer, size_t size) {
    if (nullptr == buffer) {
      return unexpected{std::make_error_code(std::errc::bad_address)};
    }

    return std::visit(
        overload{
          [](disconnected&){
            return WriteResult{unexpected{not_connected_ec()}};
          },
          [](connecting&){
            return WriteResult{unexpected{not_connected_ec()}};
          },
          [this, buffer, size](connected& context){
            const size_t send_buf_size = crypto_box_NONCEBYTES +
                                         crypto_box_MACBYTES +
                                         size;
            unsigned char send_buf[send_buf_size];
            unsigned char* nonce = send_buf;
            unsigned char* ciphertext = send_buf + crypto_box_NONCEBYTES;

            randombytes_buf(nonce, crypto_box_NONCEBYTES);

            int encrypt_result = crypto_box_easy(
                ciphertext,
                static_cast<const unsigned char*>(buffer), size,
                nonce,
                context.peer_publickey, context.secretkey);

            if (0 != encrypt_result) {
              return WriteResult{unexpected{protocol_error_ec()}};
            }

            auto result = internal_stream_.write(send_buf, send_buf_size);
            return WriteResult{std::move(result)};
          },
          [](disconnecting&){
            return WriteResult{unexpected{not_connected_ec()}};
          }
        },
        state_);
  }

  ReadResult read(void* buffer, size_t size) {
    if (nullptr == buffer) {
      return unexpected{std::make_error_code(std::errc::bad_address)};
    }

    return std::visit(
        overload{
          [](disconnected&){
            return ReadResult{unexpected{not_connected_ec()}};
          },
          [](connecting&){
            return ReadResult{unexpected{not_connected_ec()}};
          },
          [this, buffer, size](connected& context){
            const size_t recv_buffer_len = size +
                                           crypto_box_NONCEBYTES +
                                           crypto_box_MACBYTES;
            unsigned char recv_buffer[recv_buffer_len];

            // FIXME: I NEED to check the size of the received message.
            //        This must return it.
            auto result = internal_stream_.read(recv_buffer, recv_buffer_len);

            // if (recv_size < crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
            //   return ReadResult{unexpected{bad_message_ec()}};
            // }

            unsigned char* nonce = recv_buffer;
            unsigned char* ciphertext = recv_buffer + crypto_box_NONCEBYTES;
            const size_t ciphertext_len = recv_buffer_len -
                                          crypto_box_NONCEBYTES;

            int decrypt_result = crypto_box_open_easy(
                static_cast<unsigned char*>(buffer),
                ciphertext, ciphertext_len,
                nonce,
                context.peer_publickey, context.secretkey);

            if (0 != decrypt_result) {
              return ReadResult{unexpected{bad_message_ec()}};
            }

            return expected<decltype(result), std::error_code>{
              std::move(result)};
          },
          [](disconnecting&){
            return ReadResult{unexpected{not_connected_ec()}};
          }
        },
        state_);
  }

  // TODO: This should probably have a parameter with a reason of closing.
  //       The info could be sent to the remote peer.
  std::error_code close() {
    return std::visit(
        overload{
          [](disconnected&){ return not_connected_ec(); },
          [](connecting&){ return not_connected_ec(); },
          [this](connected&){
            // TODO: close connection
            internal_stream_.close();
            state_ = disconnected{};
            return std::error_code{};
          },
          [](disconnecting&){ return not_connected_ec(); }
        },
        state_);
  }
};
