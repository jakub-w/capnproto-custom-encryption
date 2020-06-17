#ifndef SSW_SODIUM_CIPHER_STREAM_H
#define SSW_SODIUM_CIPHER_STREAM_H

#include <cassert>
#include <variant>
#include <vector>
#include <system_error>

#include <sodium.h>

namespace crypto {

using byte = unsigned char;
using Bytes = std::vector<byte>;

static const auto
NA_SS_ABYTES = crypto_secretstream_xchacha20poly1305_ABYTES;
static const auto
NA_SS_KEYBYTES = crypto_secretstream_xchacha20poly1305_KEYBYTES;
static const auto
NA_SS_HEADERBYTES = crypto_secretstream_xchacha20poly1305_HEADERBYTES;

/// Fist method to call MUST be /ref Initialize(). It will return the header
/// that the peer will need in order to decrypt data encrypted here.
///
/// Then /ref Encrypt() can be called to encrypt messages.
///
/// To get finishing message call /ref Finish(). It should be sent to the peer
/// to destroy the decryption context on his end and let him know we're
/// finished. This step is optional.
/// This will also invalidate this object. It can be then reinitialized with
/// another call to \ref Initialize(). The entirely new context will be
/// created.
///
/// If \ref Initialize() is called when the context is valid, the new context
/// will replace it and the old one is gone.
class SodiumEncryptionContext final {
 public:
  /// Create an uninitialized context. Call \ref Initialize() on it.
  SodiumEncryptionContext();
  SodiumEncryptionContext(SodiumEncryptionContext&&); // = delete;
  SodiumEncryptionContext(const SodiumEncryptionContext&) = delete;

  SodiumEncryptionContext& operator=(SodiumEncryptionContext&&);
  SodiumEncryptionContext& operator=(const SodiumEncryptionContext&) = delete;

  /// Initializes the context so that the \ref Encrypt() method can be called.
  ///
  /// \anchor Initialize_doc
  /// \param[in] key Secret encryption key, must be \ref NA_SS_KEYBYTES long.
  /// \param[in] key_length Length of a \e key. This parameter is here just to
  /// be safe.
  /// \param[out] header A pointer to where an encryption header should be
  /// stored. The length of the allocated memory must be at least
  /// \ref NA_SS_HEADERBYTES. The header then needs to be passed to the peer
  /// so he's able to initialize \ref SodiumDecryptionContext with it.
  /// \param[in] header_length Length of the array \e header points to.
  ///
  /// \return \e std::errc::invalid_argument if the key or header length
  /// is wrong.
  std::error_code Initialize(const byte* key, size_t key_length,
                             byte* header, size_t header_length) noexcept;

  /// Initialize the context and get a header needed by the peer to decrypt
  /// messages encrypted by this object.
  ///
  /// \param[in] key An encryption key, must be \ref NA_SS_KEYBYTES long.
  ///
  /// \return Either error code or the header.
  ///
  /// More info at \ref Initialize_doc Initialize().
  inline std::variant<std::error_code, Bytes> Initialize(const Bytes& key) {
    auto header = Bytes(NA_SS_HEADERBYTES);
    auto ec = Initialize(key.data(), key.size(),
                         header.data(), header.size());
    if (ec) return ec;
    else return header;
  }

  /// \anchor Encrypt_doc
  /// \param[in] input Array of plain bytes to be encrypted.
  /// \param[in] input_length Length of \e input.
  /// \param[out] output Pointer to already allocated memory to store
  /// ciphertext in. The size of the array must be at least \e input_length +
  /// \ref NA_SS_ABYTES - the resulting ciphertext will be exactly that size.
  /// \param[in] output_length Length of \e output.
  ///
  /// \return \e std::errc::operation_not_permitted if the context is
  /// uninitialized.
  /// \return \e std::errc::invalid_argument if \e output is too short.
  std::error_code Encrypt(const byte* input, size_t input_length,
                          byte* output, size_t output_length) noexcept;

  /// Encrypt \e input and store it in the \e output. The \e output will be
  /// resized to fit the ciphertext perfectly.
  ///
  /// \return More info at \ref Encrypt_doc Encrypt().
  inline std::error_code Encrypt(const Bytes& input, Bytes& output) noexcept {
    output.resize(input.size() + NA_SS_ABYTES);
    return Encrypt(input.data(), input.size(), output.data(), output.size());
  }

  /// Encrypt \e input.
  ///
  /// \return Either an error code or resulting cyphertext.
  /// More info at \ref Encrypt_doc Encrypt().
  inline std::variant<std::error_code, Bytes> Encrypt(const Bytes& input) {
    Bytes output(input.size() + NA_SS_ABYTES);
    auto ec = Encrypt(input.data(), input.size(),
                      output.data(), output.size());
    if (ec) return ec;
    else return output;
  }

  /// Get the finishing message to end the stream. This will render this
  /// object unusable. The message can be passed to the peer to let him know
  /// we're finishing here.
  /// \anchor Finish_doc
  ///
  /// \param[out] output is the finishing message that should be sent to the
  /// peer.
  /// \param[in] output_length must be at least \ref NA_SS_ABYTES long.
  ///
  /// \return \e std::errc::operation_not_permitted if the context is not
  /// initialized
  /// \return \e std::errc::invalid_argument if \e output is too short.
  std::error_code Finish(byte* output, size_t output_length) noexcept;

  /// Get the finishing message to end the stream. This will render this
  /// object unusable. The returned message can be sent to the peer.
  ///
  /// \return Either an error code or the message.
  /// More info at \ref Finish_doc Finish().
  inline std::variant<std::error_code, Bytes> Finish() {
    Bytes output(NA_SS_ABYTES);
    auto ec = Finish(output.data(), output.size());
    if (ec) return ec;
    else return output;
  }

  /// Check if the context is initialized. If it's not, \ref Encrypt() and
  /// \ref Finish() methods won't work.
  inline bool Initialized() const noexcept {
    return initialized_;
  }

 private:
  crypto_secretstream_xchacha20poly1305_state state_;
  bool initialized_ = false;
};

/// \brief Context for decryption.
///
/// Call \ref Initialize() to initialize the context. This is a crucial step.
/// Then use \ref Decrypt() to decrypt messages encrypted by the peer.
///
/// When \ref Decrypt() is used on a message generated by
/// \ref SodiumEncryptionContext::Finish() the context becomes invalid and
/// uninitialized. It can be reused by calling \ref Initialize() again.
///
/// If \ref Initialize() is called when the context is valid, the new context
/// will replace it and the old one is gone.
class SodiumDecryptionContext final {
 public:
  /// Create an uninitialized decryption context.
  SodiumDecryptionContext();
  SodiumDecryptionContext(SodiumDecryptionContext&&);
  SodiumDecryptionContext(const SodiumDecryptionContext&) = delete;

  SodiumDecryptionContext& operator=(SodiumDecryptionContext&&);
  SodiumDecryptionContext& operator=(const SodiumDecryptionContext&) = delete;

  /// Initialize the context.
  /// /anchor Initialize_doc
  ///
  /// Length parameters (\e key_length and \e header_length) should be
  /// unnecessary because the length of a key and a header are fixed, but
  /// we're checking them regardless to be sure there are no mistakes by the
  /// programmer.
  ///
  /// \param[in] key Encryption key. Must be \ref NA_SS_KEYBYTES long.
  /// \param[in] key_length Length of the \e key.
  /// \param[in] header Header received from peer. Must be NA_SS_HEADERBYTES
  /// long.
  /// \param[in] header_length Lenght of the \e header.
  ///
  /// \return \e std::errc::invalid_argument if \e key or \e header don't have
  /// required lengths or if the \e header is invalid.
  std::error_code Initialize(
      const byte* key, size_t key_length,
      const byte* header, size_t header_length) noexcept;

  /// Initialize the context with a secret encryption \e key and a \e header
  /// received from the peer.
  ///
  /// \return Error code if something's wrong.
  /// More info at \ref Initialize_doc Initialize().
  inline std::error_code Initialize(const Bytes& key, const Bytes& header)
      noexcept {
    return Initialize(key.data(), key.size(), header.data(), header.size());
  }

  /// Decrypt a message \e input and store it in \e output.
  /// \anchor Decrypt_doc
  ///
  /// If the message passed as an \e input is a finishing message generated
  /// by \ref SodiumEncryptionContext::Finish() the context becomes invalid
  /// and uninitialized. It can be reused by calling \ref Initialize() again.
  ///
  /// \param[in] input Ciphertext message to be decrypted.
  /// \param[in] input_length Length of \e input.
  /// \param[out] output An already allocated space for the decrypted message.
  /// Needs to be at least \e input_length - \e NA_SS_ABYTES long. The
  /// output message will be exactly that long.
  /// \param[in] output_length Length of the \e output.
  ///
  /// \return \e std::errc::operation_not_permitted if the context is
  /// uninitialized.
  /// \return \e std::errc::invalid_argument if \e input or \e output are too
  /// short.
  /// \return \e std::errc::bad_message if a message stored at \e input is
  /// invalid, incomplete or corrupt.
  /// \return \e std::errc::connection_aborted if \e input stores a finishing
  /// message.
  std::error_code Decrypt(const byte* input, size_t input_length,
                          byte* output, size_t output_length) noexcept;

  /// Decrypt \e input and store the result in \e output.
  ///
  /// More info at \ref Decrypt_doc Decrypt().
  std::error_code Decrypt(const Bytes& input, Bytes& output) noexcept;

  /// Decrypt \e input.
  ///
  /// More info at \ref Decrypt_doc Decrypt().
  ///
  /// \return Either an error code or decrypted bytes.
  inline std::variant<std::error_code, Bytes> Decrypt(const Bytes& input) {
    Bytes output(input.size());
    auto ec = Decrypt(input, output);
    if (ec) return ec;
    else return output;
  }

  /// Check if the context is initialized. If it's not, \ref Decrypt() method
  /// won't work.
  inline bool Initialized() const noexcept {
    return initialized_;
  }

 private:
  crypto_secretstream_xchacha20poly1305_state state_;
  bool initialized_ = false;
};
}

#endif // SSW_SODIUM_CIPHER_STREAM_H
