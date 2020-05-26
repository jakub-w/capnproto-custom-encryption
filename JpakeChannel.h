#pragma once

#include <cassert>
#include <system_error>
#include <type_traits>
#include <variant>
#include <netinet/in.h>

#include <sodium.h>

#include "tl/expected.hpp"
#include "EncryptionCommon.h"

/// A channel that handshakes and derives an encryption key by using J-PAKE
/// algorithm.
template<class IoStream>
class JpakeChannel {
  struct uninitialized{};
  struct initializing{};
  struct disconnected{};
  struct connecting{};
  struct connected{
    connected(const EcPoint& key_material) {
      // TODO: make a real key out of key_material and create
      //       SodiumCipherStream.
    }

  };
  struct disconnecting{};

  using State = std::variant< uninitialized,
                              initializing,
                              disconnected,
                              connecting,
                              connected,
                              disconnecting >;

  // PRIVATE FIELDS
  State state_ = uninitialized{};
  IoStream& internal_stream_;

  EcScalar secret_;
  std::string id_;

  // PRIVATE METHODS
  std::error_code write_all(const byte* buffer, size_t size) {
    size_t sent = 0;
    while (sent < size) {
      sent += internal_stream_.write(buffer + sent, size - sent);
    }
    if (sent != size) {
      return protocol_error_ec();
    }

    return std::error_code{};
  }

  std::error_code write_zkp(const zkp& zkp) {
    std::error_code ec;
    if (zkp.user_id.size() > UINT32_MAX) {
      return std::make_error_code(std::errc::value_too_large);
    }
    uint32_t size = zkp.user_id.size();
    size = htonl(size);
    ec = write_all(size, sizeof size);
    if (ec) return ec;
    ec = write_all(zkp.user_id.data(), zkp.user_id.size());
    if (ec) return ec;
    ec = write_all(zkp.V.data(), zkp.V.size());
    if (ec) return ec;
    ec = write_all(zkp.r.data(), zkp.r.size());
    return ec;
  }

  std::error_code read_all(byte* buffer, size_t size) {
    size_t read = 0;
    while (read < size) {
      read += internal_stream_.read(buffer + read, size - read);
    }
    if (read != size) {
      return protocol_error_ec();
    }

    return std::error_code{};
  }

  std::error_code read_zkp(zkp& zkp) {
    std::error_code ec;
    uint32_t size = 0;
    ec = read_all(&size, sizeof size);
    if (ec) return ec;

    size = ntohl(size);

    // TODO: Document it. Id sent in ZKP has to be at most 128 bytes long.
    if (size > 128) {
      return std::make_error_code(std::errc::value_too_large);
    }

    ec = read_all(zkp.user_id, size);
    if (ec) return ec;
    ec = read_all(zkp.V.data(), zkp.V.size());
    if (ec) return ec;
    ec = read_all(zkp.r.data(), zkp.r.size());
    return ec;
  }

 public:
  JpakeChannel(IoStream& stream) : internal_stream_{stream} {}

  JpakeChannel() = delete;
  JpakeChannel(const JpakeChannel&) = delete;
  JpakeChannel(JpakeChannel&&) = delete;
  JpakeChannel operator=(const JpakeChannel&) = delete;
  JpakeChannel operator=(JpakeChannel&&) = delete;

  ~JpakeChannel() {
    sodium_memzero(secret_.data(), secret_.size());
  }

  /// Returns \e std::errc::already_connected if already initialized.
  ///
  /// \param id Unique id for the client/server.
  std::error_code initialize(std::string_view password,
                             std::string_view id) {
    // TODO: Make a generator out of the password and add it to the store.
    //       Can store be a linked list so that we can pass only pointers
    //       around and remove nodes quickly? Will it be secure? Definitely
    //       a custom allocator has to be used (for zeroing out the memory
    //       after deletion). Also every node should have a reference count.
    //       A store could be a hashmap with plaintext passwords as keys.
    // This is more complicated. std::string cannot be relied on using a
    // deallocate(). This needs a custom class that works with bare memory.
    // Use sodium_memzero(), sodium_mlock(), sodium_munlock(), sodium_malloc()
    // sodium_allocarray(), sodium_free().
    return std::visit(
        overload{
          [this, password, id](uninitialized&){
            state_ = initializing{};
            id_ = id;
            secret_ = make_secret(password);
            state_ = disconnected{};
          },
          [](initializing&){ return initialization_pending_ec(); },
          [](disconnected&){ return already_initialized_ec(); },
          [](connecting&){ return already_initialized_ec(); },
          [](connected&){ return already_initialized_ec(); },
          [](disconnecting&){ return already_initialized_ec(); }
        },
        state_);
  }

  /// \return \e std::errc::not_connected if uninitialized.
  /// std::errc::protocol_error when write or read from peer failed.
  std::error_code connect() {
    return std::visit(
        overload{
          // FIXME: Come up with better error codes. Probably a custom cat.
          [](uninitialized&){ return uninitialized_ec(); },
          [](initializing&){ return try_again_ec(); },
          [this](disconnected&){
            state_ = connecting{};

            EcScalar privkey1, privkey2;
            EcPoint pubkey1, pubkey2;

            // Generate random privkeys.
            // TODO: Check if the privkeys are not 0.
            //       Probably done by libsodium already.
            crypto_core_ristretto255_scalar_random(privkey1.data());
            crypto_core_ristretto255_scalar_random(privkey2.data());

            crypto_scalarmult_ristretto255_base(pubkey1.data(),
                                                privkey1.data());
            crypto_scalarmult_ristretto255_base(pubkey2.data(),
                                                privkey2.data());

            // Make ZKPs for privkey1 and privkey2.
            auto zkp1 = make_zkp(id_, privkey1, pubkey1, basepoint);
            auto zkp2 = make_zkp(id_, privkey2, pubkey2, basepoint);

            // Send pubkeys and ZKPs to peer.
            std::error_code ec;
            ec = write_all(pubkey1.data(), pubkey1.size());
            if (ec) return protocol_error_ec();
            ec = write_all(pubkey2.data(), pubkey2.size());
            if (ec) return protocol_error_ec();
            ec = write_zkp(zkp1);
            if (ec) return protocol_error_ec();
            ec = write_zkp(zkp2);
            if (ec) return protocol_error_ec();

            // Receive pubkeys and ZKPs from peer.
            EcPoint peer_pubkey1, peer_pubkey2, peer_pubkey3;
            ec = read_all(peer_pubkey1.data(), peer_pubkey1.size());
            if (ec) return protocol_error_ec();
            ec = read_all(peer_pubkey2.data(), peer_pubkey2.size());
            if (ec) return protocol_error_ec();
            ec = read_all(peer_pubkey3.data(), peer_pubkey3.size());
            if (ec) return protocol_error_ec();

            zkp peer_zkp1, peer_zkp2, peer_zkp3;
            ec = read_zkp(peer_zkp1);
            if (ec) return protocol_error_ec();
            ec = read_zkp(peer_zkp2);
            if (ec) return protocol_error_ec();
            ec = read_zkp(peer_zkp3);
            if (ec) return protocol_error_ec();

            // Verify ZKPs.
            if (not check_zkp(peer_zkp1, peer_pubkey1, id_, basepoint)) {
              return permission_denied_ec();
            }
            if (not check_zkp(peer_zkp2, peer_pubkey2, id_, basepoint)) {
              return permission_denied_ec();
            }

            // Last zkp has a different generator.
            // G1 = pubkey1 + pubkey2 + peer_pubkey1
            EcPoint peer_zkp_gen;
            crypto_core_ristretto255_add(peer_zkp_gen.data(),
                                         pubkey1.data(),
                                         pubkey2.data());
            crypto_core_ristretto255_add(peer_zkp_gen.data(),
                                         peer_zkp_gen.data(),
                                         peer_pubkey1.data());
            if (not crypto_core_ristretto255_is_valid_point(
                    peer_zkp_gen.data())) {
              return permission_denied_ec();
            }
            // TODO: Check if peer_zkp_gen is not a point at infinity.
            if (not check_zkp(peer_zkp3, peer_pubkey3, id_, peer_zkp_gen)) {
              return permission_denied_ec();
            }

            // Send pubkey3 and ZKP for it.
            // G2 = pubkey1 + peer_pubkey1 + peer_pubkey2
            EcPoint zkp_gen;
            crypto_core_ristretto255_add(
                zkp_gen.data(), pubkey1.data(), peer_pubkey1.data());
            crypto_core_ristretto255_add(
                zkp_gen.data(), zkp_gen.data(), peer_pubkey2.data());
            // privkey3 = privkey2 * secret_
            EcScalar privkey3;
            crypto_core_ristretto255_scalar_add(
                privkey3.data(), privkey2.data(), secret_.data());
            // pubkey3 = G2 * privkey3
            EcPoint pubkey3;
            crypto_scalarmult_ristretto255(
                pubkey3.data(), privkey3.data(), zkp_gen.data());

            auto zkp3 = make_zkp(id_, privkey3, pubkey3, zkp_gen);

            ec = write_all(pubkey3.data(), pubkey3.size());
            if (ec) return protocol_error_ec();
            ec = write_zkp(zkp3);
            if (ec) return protocol_error_ec();

            // Compute the session key material
            // K = (peer_pubkey3 - (peer_pubkey2 x [privkey2 * secret_]))
            //         x [privkey2]
            // TODO

            // TODO: pass the encryption key to connected object
            state_ = connected{};

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
          [](uninitialized&){ return uninitialized_ec(); },
          [](initializing&){ return try_again_ec(); },
          [this](disconnected&){
            state_ = connecting{};
            // TODO
          },
          [](connecting&){ return connection_pending_ec(); },
          [](connected&){ return already_connected_ec(); },
          [](disconnecting&){ return try_again_ec(); }
        },
        state_);
  }

  WriteResult write(const void* buffer, size_t size) {
    assert(nullptr != buffer);
#ifdef NDEBUG
    if (nullptr != buffer) {
      return unexpected{std::make_error_code(std::errc::bad_address)};
    }
#endif

    return std::visit(
        overload{
          [](uninitialized&){
            return WriteResult{unexpected{uninitialized_ec()}};
          },
          [](initializing&){
            return WriteResult{unexpected{not_connected_ec()}};
          },
          [](disconnected&){
            return WriteResult{unexpected{not_connected_ec()}};
          },
          [](connecting&){
            return WriteResult{unexpected{not_connected_ec()}};
          },
          [](connected&){
            // TODO
          },
          [](disconnecting&){
            return WriteResult{unexpected{not_connected_ec()}};
          }
        },
        state_);
  }

  ReadResult read(void* buffer, size_t size) {
    assert(nullptr != buffer);
#ifdef NDEBUG
    if (nullptr != buffer) {
      return unexpected{std::make_error_code(std::errc::bad_address)};
    }
#endif

    return std::visit(
        overload{
          [](uninitialized&){
            return ReadResult{unexpected{uninitialized_ec()}};
          },
          [](initializing&){
            return ReadResult{unexpected{not_connected_ec()}};
          },
          [](disconnected&){
            return ReadResult{unexpected{not_connected_ec()}};
          },
          [](connecting&){
            return ReadResult{unexpected{not_connected_ec()}};
          },
          [](connected&){
            // TODO
          },
          [](disconnecting&){
            return ReadResult{unexpected{not_connected_ec()}};
          }
        },
        state_);
  }

  std::error_code close() {
    return std::visit(
        overload{
          [](uninitialized&){ return not_connected_ec(); },
          [](initializing&){ return not_connected_ec(); },
          [](disconnected&){ return not_connected_ec(); },
          [](connecting&){
            // TODO
          },
          [](connected&){
            // TODO
          },
          [](disconnecting&){ return not_connected_ec(); }
        },
        state_);
  }
};

// TODO: Lock a mutex when calling methods?
// TODO: Returning error codes from connect() may be not enough.
//       Maybe the connection should be closed depending on an error?
// FIXME: Check if the peer uses the same identity throughout the whole
//        process. I.e. check user_id's from ZKPs.
