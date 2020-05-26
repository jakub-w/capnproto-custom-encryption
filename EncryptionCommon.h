#include <system_error>

#include <sodium.h>

#include "tl/expected.hpp"

namespace {
using tl::expected;
using tl::unexpected;

template<class... Ts> struct overload : Ts... { using Ts::operator()...; };
template<class... Ts> overload(Ts...) -> overload<Ts...>;

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
static inline std::error_code incomplete_write_ec() {
  return std::make_error_code(std::errc::message_size);
}

using byte = unsigned char;
using EcPoint = std::array<byte, crypto_core_ristretto255_BYTES>;
using EcScalar = std::array<byte, crypto_core_ristretto255_SCALARBYTES>;
};
