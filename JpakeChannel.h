#pragma once

#include <cassert>
#include <system_error>
#include <type_traits>
#include <variant>
#include <netinet/in.h>

#include <sodium.h>

#include "tl/expected.hpp"
#include "EncryptionCommon.h"
#include "SodiumCipherStream.h"

/// A channel that handshakes and derives an encryption key by using J-PAKE
/// algorithm.
template<class IoStream>
class JpakeChannel {
  // TODO: Change the type to something safe
  using EncryptionKey = std::array<byte, crypto::NA_SS_KEYBYTES>;
  using EncryptionHeader = std::array<byte, crypto::NA_SS_HEADERBYTES>;

  struct uninitialized{};
  struct initializing{};
  struct disconnected{};
  struct connecting{};
  struct connected{
    crypto::SodiumEncryptionContext enc_ctx;
    crypto::SodiumDecryptionContext dec_ctx;
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
      const auto result = internal_stream_.write(buffer + sent, size - sent);
      if (not result) return result.error();
      sent += result.value();
    }
    if (sent != size) {
      return protocol_error_ec();
    }

    return std::error_code{};
  }

  std::error_code write_zkp(const zkp& zkp) {
    static_assert(sizeof(typename decltype(zkp.user_id)::value_type)
                  == sizeof(byte));
    std::error_code ec;
    if (zkp.user_id.size() > UINT32_MAX) {
      return std::make_error_code(std::errc::value_too_large);
    }
    uint32_t size = zkp.user_id.size();
    size = htonl(size);
    ec = write_all(reinterpret_cast<const byte*>(&size), sizeof(size));
    if (ec) return ec;
    ec = write_all(reinterpret_cast<const byte*>(zkp.user_id.data()),
                   zkp.user_id.size());
    if (ec) return ec;
    ec = write_all(zkp.V.data(), zkp.V.size());
    if (ec) return ec;
    ec = write_all(zkp.r.data(), zkp.r.size());
    return ec;
  }

  std::error_code read_all(byte* buffer, size_t size) {
    size_t read = 0;
    while (read < size) {
      const auto result = internal_stream_.read(buffer + read, size - read);
      if (not result) return result.error();
      read += result.value();
    }
    if (read != size) {
      return protocol_error_ec();
    }

    return std::error_code{};
  }

  std::error_code read_zkp(zkp& zkp) {
    std::error_code ec;
    uint32_t size = 0;
    ec = read_all(reinterpret_cast<byte*>(&size), sizeof(size));
    if (ec) return ec;

    size = ntohl(size);

    // TODO: Document it. Id sent in ZKP has to be at most 128 bytes long.
    if (size > 128) {
      return std::make_error_code(std::errc::value_too_large);
    }

    zkp.user_id.resize(size);
    ec = read_all(reinterpret_cast<byte*>(zkp.user_id.data()), size);
    if (ec) return ec;
    ec = read_all(zkp.V.data(), zkp.V.size());
    if (ec) return ec;
    ec = read_all(zkp.r.data(), zkp.r.size());
    return ec;
  }

  EcPoint make_key_material(const EcPoint& peer_pubkey3,
                            const EcPoint& peer_pubkey2,
                            const EcScalar& privkey2,
                            const EcScalar& secret) {
    // K = (peer_pubkey3 - (peer_pubkey2 x [privkey2 * secret_])) x [privkey2]
    EcPoint key_material;
    EcScalar temp_scalar;
    // temp_scalar = [privkey2 * secret]
    crypto_core_ristretto255_scalar_mul(
        temp_scalar.data(), privkey2.data(), secret.data());
    // key_material = peer_pubkey2 x temp_scalar
    crypto_scalarmult_ristretto255(
        key_material.data(), temp_scalar.data(), peer_pubkey2.data());
    // key_material = peer_pubkey3 - key_material
    crypto_core_ristretto255_sub(
        key_material.data(),
        peer_pubkey3.data(), key_material.data());
    // key_material = key_material x [privkey2]
    crypto_scalarmult_ristretto255(
        key_material.data(), privkey2.data(), key_material.data());

    return key_material;
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

            return std::error_code{};
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

            auto [privkey1, pubkey1, zkp1] = generate_keypair(id_);
            auto [privkey2, pubkey2, zkp2] = generate_keypair(id_);

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
            const std::string& peer_id = peer_zkp1.user_id;
            if (not check_zkp(peer_zkp1, peer_pubkey1, peer_id,
                              id_, basepoint)) {
              return permission_denied_ec();
            }
            if (not check_zkp(peer_zkp2, peer_pubkey2, peer_id,
                              id_, basepoint)) {
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

            if (not check_zkp(peer_zkp3, peer_pubkey3, peer_id,
                              id_, peer_zkp_gen)) {
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
            crypto_core_ristretto255_scalar_mul(
                privkey3.data(), privkey2.data(), secret_.data());
            // pubkey3 = G2 * privkey3
            EcPoint pubkey3;
            crypto_scalarmult_ristretto255(
                pubkey3.data(), privkey3.data(), zkp_gen.data());

            const auto zkp3 = make_zkp(id_, privkey3, pubkey3, zkp_gen);

            ec = write_all(pubkey3.data(), pubkey3.size());
            if (ec) return protocol_error_ec();
            ec = write_zkp(zkp3);
            if (ec) return protocol_error_ec();

            // Compute the session key material
            // K = (peer_pubkey3 - (peer_pubkey2 x [privkey2 * secret_]))
            //         x [privkey2]
            const EcPoint key_material = make_key_material(
                peer_pubkey3, peer_pubkey2, privkey2, secret_);

            // Key confirmation
            // Generate a signing key: k' = KDF(K || 1 || "JW_KGEN")
            HmacKey kc_key;
            // Generate an encryption keys: EK = KDF(K || 2 || "JW_KGEN")
            //                              DK = KDF(K || 3 || "JW_KGEN")
            EncryptionKey enc_key, dec_key;

            // The order of args is important! Note that dec_key and enc_key
            // are in inverted order to the one in accept().
            derive_keys(key_material, kc_key, enc_key, dec_key);

            const auto kc =
                make_key_confirmation(kc_key,
                                      id_, pubkey1, pubkey2,
                                      peer_id, peer_pubkey1, peer_pubkey2);

            // Send key confirmation data to peer.
            ec = write_all(kc.data(), kc.size());
            if (ec) return protocol_error_ec();

            // Receive and verify key confirmation data from peer.
            HmacHash peer_kc;
            ec = read_all(peer_kc.data(), peer_kc.size());
            if (ec) return protocol_error_ec();

            const auto expected_peer_kc =
                make_key_confirmation(kc_key,
                                      peer_id, peer_pubkey1, peer_pubkey2,
                                      id_, pubkey1, pubkey2);
            if (peer_kc != expected_peer_kc) {
              return permission_denied_ec();
            }

            connected state = connected{};

            // Receive the encryption header from peer and create decryption
            // context with it.
            EncryptionHeader peer_enc_header;
            ec = read_all(peer_enc_header.data(), peer_enc_header.size());
            if (ec) return protocol_error_ec();

            ec = state.dec_ctx.Initialize(
                dec_key.data(), dec_key.size(),
                peer_enc_header.data(), peer_enc_header.size());
            if (ec) permission_denied_ec();

            // Create the encryption context and send the header to peer
            EncryptionHeader enc_header;
            ec = state.enc_ctx.Initialize(
                enc_key.data(), enc_key.size(),
                enc_header.data(), enc_header.size());
            if (ec) protocol_error_ec();

            ec = write_all(enc_header.data(), enc_header.size());
            if (ec) protocol_error_ec();

            assert(state.dec_ctx.Initialized());
            assert(state.enc_ctx.Initialized());

            state_ = std::move(state);

            return ec;
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

            // Receive first two public keys and ZKPs for them
            std::error_code ec;
            EcPoint peer_pubkey1, peer_pubkey2;
            ec = read_all(peer_pubkey1.data(), peer_pubkey1.size());
            if (ec) return protocol_error_ec();
            ec = read_all(peer_pubkey2.data(), peer_pubkey2.size());
            if (ec) return protocol_error_ec();
            zkp peer_zkp1, peer_zkp2;
            ec = read_zkp(peer_zkp1);
            if (ec) return protocol_error_ec();
            ec = read_zkp(peer_zkp2);
            if (ec) return protocol_error_ec();

            std::string& peer_id = peer_zkp1.user_id;

            // Check the received ZKPs
            if (not check_zkp(peer_zkp1, peer_pubkey1, peer_id, id_)) {
              return permission_denied_ec();
            }
            if (not check_zkp(peer_zkp2, peer_pubkey2, peer_id, id_)) {
              return permission_denied_ec();
            }

            // Generate keys and ZKPs.
            auto [privkey1, pubkey1, zkp1] = generate_keypair(id_);
            auto [privkey2, pubkey2, zkp2] = generate_keypair(id_);

            // The last one is special:
            // G1 = peer_pubkey1 + peer_pubkey2 + pubkey1
            EcPoint zkp_gen;
            crypto_core_ristretto255_add(
                zkp_gen.data(), peer_pubkey1.data(), peer_pubkey2.data());
            crypto_core_ristretto255_add(
                zkp_gen.data(), zkp_gen.data(), pubkey1.data());
            // privkey3 = privkey2 * secret_
            EcScalar privkey3;
            crypto_core_ristretto255_scalar_mul(
                privkey3.data(), privkey2.data(), secret_.data());
            // pubkey3 = G1 * privkey3
            EcPoint pubkey3;
            crypto_scalarmult_ristretto255(
                pubkey3.data(), privkey3.data(), zkp_gen.data());

            const auto zkp3 = make_zkp(id_, privkey3, pubkey3, zkp_gen);

            // Send all public keys and ZKPs
            ec = write_all(pubkey1.data(), pubkey1.size());
            if (ec) return protocol_error_ec();
            ec = write_all(pubkey2.data(), pubkey2.size());
            if (ec) return protocol_error_ec();
            ec = write_all(pubkey3.data(), pubkey3.size());
            if (ec) return protocol_error_ec();
            ec = write_zkp(zkp1);
            if (ec) return protocol_error_ec();
            ec = write_zkp(zkp2);
            if (ec) return protocol_error_ec();
            ec = write_zkp(zkp3);
            if (ec) return protocol_error_ec();

            // Receive peer_pubkey3 and ZKP for it
            EcPoint peer_pubkey3;
            ec = read_all(peer_pubkey3.data(), peer_pubkey3.size());
            if (ec) return protocol_error_ec();
            zkp peer_zkp3;
            ec = read_zkp(peer_zkp3);
            if (ec) return protocol_error_ec();

            // Verify
            // G2 = peer_pubkey1 + pubkey1 + pubkey2
            EcPoint peer_zkp_gen;
            crypto_core_ristretto255_add(
                peer_zkp_gen.data(), peer_pubkey1.data(), pubkey1.data());
            crypto_core_ristretto255_add(
                peer_zkp_gen.data(), peer_zkp_gen.data(), pubkey2.data());
            if (not crypto_core_ristretto255_is_valid_point(
                    peer_zkp_gen.data())) {
              return permission_denied_ec();
            }
            if (not check_zkp(
                    peer_zkp3, peer_pubkey3, peer_id, id_, peer_zkp_gen)) {
              return permission_denied_ec();
            }

            // Compute the session key material
            // K = (peer_pubkey3 - (peer_pubkey2 x [privkey2 * secret_]))
            //         x [privkey2]
            const EcPoint key_material = make_key_material(
                peer_pubkey3, peer_pubkey2, privkey2, secret_);

            // Key confirmation
            // Generate a signing key: k' = KDF(K || 1 || "JW_KGEN")
            HmacKey kc_key;
            // Generate an encryption keys: EK = KDF(K || 3 || "JW_KGEN")
            //                              DK = KDF(K || 2 || "JW_KGEN")
            EncryptionKey enc_key, dec_key;

            // The order of args is important! Note that dec_key and enc_key
            // are in inverted order to the one in connect().
            derive_keys(key_material, kc_key, dec_key, enc_key);

            // Receive and verify key confirmation data from peer
            HmacHash peer_kc;
            ec = read_all(peer_kc.data(), peer_kc.size());
            if (ec) return protocol_error_ec();

            const auto expected_peer_kc =
                make_key_confirmation(kc_key,
                                      peer_id, peer_pubkey1, peer_pubkey2,
                                      id_, pubkey1, pubkey2);
            if (peer_kc != expected_peer_kc) {
              return permission_denied_ec();
            }

            connected state{};

            // Create the encryption context
            EncryptionHeader enc_header;
            state.enc_ctx.Initialize(enc_key.data(), enc_key.size(),
                                     enc_header.data(), enc_header.size());

            // Generate the key confirmation data
            const auto kc =
                make_key_confirmation(kc_key,
                                      id_, pubkey1, pubkey2,
                                      peer_id, peer_pubkey1, peer_pubkey2);

            // Send key confirmation data and encryption header to peer
            ec = write_all(kc.data(), kc.size());
            if (ec) return protocol_error_ec();
            ec = write_all(enc_header.data(), enc_header.size());
            if (ec) return protocol_error_ec();

            // Receive the encryption header from peer and create decryption
            // context with it.
            EncryptionHeader peer_enc_header;
            ec = read_all(peer_enc_header.data(), peer_enc_header.size());
            if (ec) protocol_error_ec();

            ec = state.dec_ctx.Initialize(
                dec_key.data(), dec_key.size(),
                peer_enc_header.data(), peer_enc_header.size());
            if (ec) permission_denied_ec();

            assert(state.dec_ctx.Initialized());
            assert(state.enc_ctx.Initialized());

            state_ = std::move(state);

            return ec;
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
          [this, buffer, size](connected& state){
            const size_t ciphertext_size = size + crypto::NA_SS_ABYTES;
            byte ciphertext[ciphertext_size];

            std::error_code ec = state.enc_ctx.Encrypt(
                static_cast<const byte*>(buffer), size,
                ciphertext, ciphertext_size);
            if (ec) {
              // TODO: Log the real error code.
              //       It can be operation_not_permitted if the encryption
              //       context wasn't initialized, or invalid_argument if the
              //       output array isn't long enough.
              return WriteResult{unexpected{protocol_error_ec()}};
            }

            ec = write_all(ciphertext, ciphertext_size);
            if (ec) return WriteResult{unexpected{ec}};

            return WriteResult{size};
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
          [this, buffer, size](connected& context){
            const size_t ciphertext_size = size + crypto::NA_SS_ABYTES;
            byte ciphertext[ciphertext_size];

            std::error_code ec = read_all(ciphertext, ciphertext_size);
            if (ec) return ReadResult{unexpected{ec}};

            ec = context.dec_ctx.Decrypt(
                ciphertext, ciphertext_size,
                static_cast<byte*>(buffer), size);
            if (ec) {
              // TODO: Log the real reason of the error.
              //       It can be operation_not_permitted if context is
              //       uninitialized, invalid argument if input or output
              //       are too short, bad_message if the message is invalid,
              //       incomplete or corrupt, or connection_aborted if
              //       the finishing message was received.
              sodium_memzero(buffer, size);
              if (ec.value() ==
                  static_cast<int>(std::errc::connection_aborted)) {
                close();
                return ReadResult{unexpected{ec}};
              }
              return ReadResult{unexpected{protocol_error_ec()}};
            }

            return ReadResult{size};
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
            return std::error_code{};
          },
          [](connected&){
            // TODO
            return std::error_code{};
          },
          [](disconnecting&){ return not_connected_ec(); }
        },
        state_);
  }}
  ;

// TODO: Lock a mutex when calling methods?
// TODO: Returning error codes from connect() may be not enough.
//       Maybe the connection should be closed depending on an error?
// TODO: Probably log stuff before returning with an error code.
// TODO: Squash all messages that need to be sent in one step into one buffer.
//       Depending on internal_stream_'s implementation it could result in
//       faster transfers.

// NOTE: Two different keys are used for encryption and decryption.
//       The initializing party (the one that calls connect()) uses key with
//       subkey_id 2 for encryption and subkey_id 3 for decryption.
//       The server (accept()) uses subkey_id 3 for encryption and subkey_id
//       2 for decryption.

// TODO: I could make a hook for after-connect and put stuff there when
//       close() is called during connecting phase.

// FIXME: There's no way for one peer to know that the other peer exited from
//        accept/connect with an error, so it will hang indefinitely, trying
//        to read or write to it.
//        Before exiting write an error message to the peer?
//        Every read should check for an error?
//        Let's say read_all returns an error code if the access is denied.
//        What error code should the peer return? Errors shouldn't be the same
//        on both sides because that way the source of an error isn't known.
//        I denied the access or the peer denied access to me?
//        Is it time for a custom error_category?
