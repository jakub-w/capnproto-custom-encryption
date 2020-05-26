#pragma once

#include <iostream>
#include <cassert>
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
static inline std::error_code uninitialized_ec() {
  return std::make_error_code(std::errc::not_connected);
}
static inline std::error_code already_connected_ec() {
  return std::make_error_code(std::errc::already_connected);
}
static inline std::error_code already_initialized_ec() {
  return std::make_error_code(std::errc::already_connected);
}
static inline std::error_code connection_pending_ec() {
  return std::make_error_code(std::errc::connection_already_in_progress);
}
static inline std::error_code initialization_pending_ec() {
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
static inline std::error_code permission_denied_ec() {
  return std::make_error_code(std::errc::permission_denied);
}

using WriteResult = expected<size_t, std::error_code>;
using ReadResult = expected<size_t, std::error_code>;

using byte = unsigned char;
using EcPoint = std::array<byte, crypto_core_ristretto255_BYTES>;
using EcScalar = std::array<byte, crypto_core_ristretto255_SCALARBYTES>;

// Asserts to ensure that libsodium isn't incompatible.
static_assert(crypto_core_ristretto255_SCALARBYTES ==
              crypto_core_ristretto255_BYTES);
static_assert(crypto_core_ristretto255_NONREDUCEDSCALARBYTES >=
              crypto_generichash_BYTES &&
              crypto_core_ristretto255_NONREDUCEDSCALARBYTES <=
              crypto_generichash_BYTES_MAX);

template <typename It>
static void print_hex(It begin, It end) {
  for (It it = begin; it != end; ++it) {
    char s[3];
    snprintf(s, 3, "%02x", *it);
    std::cout << s;
    // std::cout << *it;
  }
  std::cout << '\n';
}

static EcPoint make_generator(std::string_view password) {
  static_assert(sizeof(decltype(password)::value_type) == sizeof(byte));

  std::array<byte, crypto_core_ristretto255_NONREDUCEDSCALARBYTES> hash;
  std::array<byte, crypto_core_ristretto255_SCALARBYTES> intermediate;
  std::array<byte, crypto_core_ristretto255_SCALARBYTES> result;

  // H(p)
  crypto_generichash(hash.data(), hash.size(),
                     reinterpret_cast<const byte*>(password.data()),
                     password.length(),
                     nullptr, 0);

  // Hash the hash, repeat it until you get a valid generator.
  for(;;) {
    // TODO: This should be tested. Current implementation of libsodium is
    //       fine with input and output being the same, but who knows what
    //       will happen in the future.
    crypto_generichash(hash.data(), hash.size(),
                       hash.data(), hash.size(),
                       nullptr, 0);

    // mod L
    crypto_core_ristretto255_scalar_reduce(result.data(), hash.data());

    // g = H(p)^2
    crypto_core_ristretto255_scalar_mul(intermediate.data(),
                                        result.data(), result.data());

    // P*g (P is the base point)
    if (0 == crypto_scalarmult_ristretto255_base(result.data(),
                                                 intermediate.data())) {
      sodium_memzero(hash.data(), hash.size());
      sodium_memzero(intermediate.data(), intermediate.size());
      return result;
    }
  }
}

// TODO: Make it more sophisticated? Use crypto_pwhash() perhaps?
static EcScalar make_secret(std::string_view password) {
  static_assert(sizeof(decltype(password)::value_type) == sizeof(byte));

  // std::array<byte, crypto_core_ristretto255_NONREDUCEDSCALARBYTES> hash;
  std::array<byte, crypto_core_ristretto255_HASHBYTES> hash;
  std::array<byte, crypto_core_ristretto255_SCALARBYTES> result;

  // H(p)
  crypto_generichash(hash.data(), hash.size(),
                     reinterpret_cast<const byte*>(password.data()),
                     password.length(),
                     nullptr, 0);

  // mod L
  // crypto_core_ristretto255_scalar_reduce(result.data(), hash.data());
  crypto_core_ristretto255_from_hash(result.data(), hash.data());

  // // s = H(p)^2
  // crypto_core_ristretto255_scalar_mul(result.data(),
  //                                     result.data(), result.data());

  sodium_memzero(hash.data(), hash.size());
  return result;
}

struct zkp {
  std::string user_id;
  // V = G x [v], where v is a random number
  EcPoint V;
  // r = v - privkey * c, where c = H(gen || V || pubkey || user_id)
  EcScalar r;
};

const static EcPoint basepoint =
    []{
      EcScalar identity = {1};
      EcPoint result;
      crypto_scalarmult_ristretto255_base(result.data(), identity.data());

      assert(std::any_of(result.begin(), result.end(),
                         [](byte b){ return b != 0; })
             && "Base point of ristretto255 seems to be 0");

      return result;
    }();

static EcScalar make_zkp_challenge(const EcPoint& V,
                                   const EcPoint& pubkey,
                                   std::string_view user_id,
                                   const EcPoint& generator) {
  static_assert(sizeof(decltype(user_id)::value_type) == sizeof(byte));

  // challenge: H(gen || V || pubkey || user_id)
  std::array<byte, crypto_core_ristretto255_HASHBYTES> hash;
  crypto_generichash_state state;
  // TODO: Probably use some kind of a key for hashing, it can be just a
  //       static salt.
  crypto_generichash_init(&state, nullptr, 0, hash.size());

  crypto_generichash_update(&state, generator.data(), generator.size());
  crypto_generichash_update(&state, V.data(), V.size());
  crypto_generichash_update(&state, pubkey.data(), pubkey.size());
  crypto_generichash_update(&state,
                            reinterpret_cast<const byte*>(user_id.data()),
                            user_id.size());
  crypto_generichash_final(&state, hash.data(), hash.size());

  EcScalar c;
  crypto_core_ristretto255_from_hash(c.data(), hash.data());

  return c;
}

static struct zkp make_zkp(std::string_view user_id,
                           const EcScalar& privkey,
                           const EcPoint& pubkey,
                           const EcPoint& generator) {
  static_assert(sizeof(decltype(user_id)::value_type) == sizeof(byte));

  zkp zkp;
  zkp.user_id = user_id;

  // random number
  EcScalar v; // FIXME: depending on this number the test fails or passes
  crypto_core_ristretto255_scalar_random(v.data());

  // V = G x [v]
  crypto_scalarmult_ristretto255(zkp.V.data(), v.data(), generator.data());
  // crypto_scalarmult_ristretto255_base(zkp.V.data(), v.data());

  // challenge: H(gen || V || pubkey || user_id)
  EcScalar c = make_zkp_challenge(zkp.V, pubkey, user_id, generator);

  // challenge response (r)
  // privkey * c
  crypto_core_ristretto255_scalar_mul(zkp.r.data(), privkey.data(), c.data());
  // TODO: Check if it's ok to make the input and output the same
  // v - (privkey * c)
  crypto_core_ristretto255_scalar_sub(zkp.r.data(), v.data(), zkp.r.data());

  return zkp;
  // TODO: Check the return values of libsodium functions.
}

static bool check_zkp(const struct zkp& zkp,
                      const EcPoint& pubkey,
                      std::string_view this_user_id,
                      const EcPoint& generator) {
  if (not crypto_core_ristretto255_is_valid_point(pubkey.data())) {
    return false;
  }
  // TODO: Check if verify checks if pubkey x [h] isn't the point at infinity.
  //       h is a cofactor of the subgroup over E(Fp) of prime order n.
  //       Does *_is_valid_point() already do it?
  if (not crypto_core_ristretto255_is_valid_point(zkp.V.data())) {
    return false;
  }
  if (not std::any_of(zkp.r.begin(), zkp.r.end(),
                      [](byte b){ return b != 0; })) {
    return false;
  }
  if (zkp.user_id == this_user_id) {
    return false;
  }

  EcPoint V, temp;
  EcScalar c = make_zkp_challenge(zkp.V, pubkey, zkp.user_id, generator);

  // G x [r]
  // crypto_scalarmult_ristretto255_base(V.data(), zkp.r.data());
  crypto_scalarmult_ristretto255(V.data(), zkp.r.data(), generator.data());
  // pubkey x [c]
  crypto_scalarmult_ristretto255(temp.data(), c.data(), pubkey.data());
  // V = G x [r] + pubkey x [c]
  crypto_core_ristretto255_add(V.data(), V.data(), temp.data());

  return V == zkp.V;
}
};

// TODO: Make EcScalar and EcPoint classes with move and copy construction
//       and assignment so we can properly zero out memory on move/copy.
// TODO: Add OtherInfo to make_zkp_challenge()'s hash?
//       Also specify the protocol so that the implementation details are
//       listed in one place and not the code.
