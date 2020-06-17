#include "SodiumCipherStream.h"

#include <algorithm>

namespace crypto {

/* #################### SodiumEncryptionContext #################### */

SodiumEncryptionContext::SodiumEncryptionContext(){}

SodiumEncryptionContext::SodiumEncryptionContext(
    SodiumEncryptionContext&& other)
    : state_{std::move(other.state_)},
      initialized_{std::exchange(other.initialized_, false)} {
  sodium_memzero(&other.state_, sizeof(other.state_));
}

SodiumEncryptionContext&
SodiumEncryptionContext::operator=(SodiumEncryptionContext&& other) {
  state_ = std::move(other.state_);
  initialized_ = std::exchange(other.initialized_, false);

  sodium_memzero(&other.state_, sizeof(other.state_));

  return *this;
}

std::error_code SodiumEncryptionContext::Initialize(
    const byte* key, size_t key_length,
    byte* header, size_t header_length) noexcept {
  initialized_ = false;
  assert(key != nullptr);
  assert(header != nullptr);
  if (key_length != NA_SS_KEYBYTES or
      header_length < NA_SS_HEADERBYTES) {
    return std::make_error_code(std::errc::invalid_argument);
  }

  crypto_secretstream_xchacha20poly1305_init_push(&state_, header, key);

  initialized_ = true;

  return std::error_code();
}

std::error_code SodiumEncryptionContext::Encrypt(
    const byte* input, size_t input_length,
    byte* output, size_t output_length) noexcept {
  assert(input != nullptr);
  assert(output != nullptr);
  if (not initialized_) {
    return std::make_error_code(std::errc::operation_not_permitted);
  }
  if (output_length < input_length + NA_SS_ABYTES) {
    return std::make_error_code(std::errc::invalid_argument);
  }

  crypto_secretstream_xchacha20poly1305_push(
      &state_,
      output, nullptr,
      input, input_length,
      nullptr, 0, 0);
  return std::error_code();
}

std::error_code SodiumEncryptionContext::Finish(
    byte* output, size_t output_length) noexcept {
  if (not initialized_) {
    return std::make_error_code(std::errc::operation_not_permitted);
  }
  if (output_length < NA_SS_ABYTES) {
    return std::make_error_code(std::errc::invalid_argument);
  }
  crypto_secretstream_xchacha20poly1305_push(
      &state_, output, nullptr, nullptr, 0, nullptr, 0,
      crypto_secretstream_xchacha20poly1305_TAG_FINAL);

  initialized_ = false;

  return std::error_code();
}

/* ################################################################# */


/* #################### SodiumDecryptionContext #################### */

SodiumDecryptionContext::SodiumDecryptionContext(){}

SodiumDecryptionContext::SodiumDecryptionContext(
    SodiumDecryptionContext&& other)
    : state_{std::move(other.state_)},
      initialized_{std::exchange(other.initialized_, false)} {
  sodium_memzero(&other.state_, sizeof(other.state_));
}

SodiumDecryptionContext&
SodiumDecryptionContext::operator=(SodiumDecryptionContext&& other) {
  state_ = std::move(other.state_);
  initialized_ = std::exchange(other.initialized_, false);

  sodium_memzero(&other.state_, sizeof(other.state_));

  return *this;
}

std::error_code SodiumDecryptionContext::Initialize(
    const byte* key, size_t key_length,
    const byte* header, size_t header_length)
    noexcept {
  initialized_ = false;
  assert(key != nullptr);
  assert(header != nullptr);
  if (key_length != NA_SS_KEYBYTES or
      header_length < NA_SS_HEADERBYTES or
      -1 == crypto_secretstream_xchacha20poly1305_init_pull(
          &state_, header, key)) {
    return std::make_error_code(std::errc::invalid_argument);
  }

  initialized_ = true;

  return std::error_code();
}

std::error_code SodiumDecryptionContext::Decrypt(
    const byte* input, size_t input_length,
    byte* output, size_t output_length) noexcept {
  assert(input != nullptr);
  assert(output != nullptr or input_length == NA_SS_ABYTES);
  if (not initialized_) {
    return std::make_error_code(std::errc::operation_not_permitted);
  }
  if (input_length < NA_SS_ABYTES or
      output_length < input_length - NA_SS_ABYTES) {
    return std::make_error_code(std::errc::invalid_argument);
  }

  byte tag;
  if (-1 == crypto_secretstream_xchacha20poly1305_pull(
          &state_,
          output, nullptr, &tag,
          input, input_length,
          nullptr, 0)) {
    return std::make_error_code(std::errc::bad_message);
  }
  if (crypto_secretstream_xchacha20poly1305_TAG_FINAL == tag) {
    initialized_ = false;
    return std::make_error_code(std::errc::connection_aborted);
  }
  return std::error_code();
}

std::error_code SodiumDecryptionContext::Decrypt(
    const Bytes& input, Bytes& output) noexcept {
  if (input.size() < NA_SS_ABYTES) { // prevent arithmetic underflow
    return std::make_error_code(std::errc::invalid_argument);
  }
  output.resize(input.size() - NA_SS_ABYTES);
  return Decrypt(input.data(), input.size(), output.data(), output.size());
}

/* ################################################################# */

}
