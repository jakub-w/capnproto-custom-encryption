#pragma once

#include <system_error>

#include "tl/expected.hpp"

// TODO: Don't include it, include some global config file instead.
#include "EncryptionCommon.h"

// If the stream implementation is a network stream it should handle
// endianness conversion.
template<typename T>
class IoStream {
 public:
  using writeResult = expected<size_t, std::error_code>;
  using readResult = expected<size_t, std::error_code>;

  inline expected<size_t, std::error_code>
  write(const void* buffer, size_t size) {
    assert(buffer);

#ifdef EXCEPTIONS_ENABLED
    try {
#endif
      // return T::write(this, buffer, size);
      return static_cast<T*>(this)->write(buffer, size);
#ifdef EXCEPTIONS_ENABLED
    } catch (const std::system_error& e) {
      return unexpected(e.code());
    } catch (...) {
      return unexpected(std::make_error_code(std::errc::io_error));
    }
#endif
  }

  inline expected<size_t, std::error_code> read(void* buffer, size_t size) {
    assert(buffer);

#ifdef EXCEPTIONS_ENABLED
    try {
#endif
      return static_cast<T*>(this)->read(buffer, size);
#ifdef EXCEPTIONS_ENABLED
    } catch (const std::system_error& e) {
      return unexpected(e.code());
    } catch (...) {
      return unexpected(std::make_error_code(std::errc::io_error));
    }
#endif
  }

  inline std::error_code close() {
#ifdef EXCEPTIONS_ENABLED
    try {
#endif
      static_cast<T*>(this)->close();
      return std::error_code{};
#ifdef EXCEPTIONS_ENABLED
    } catch (const std::system_error& e) {
      return e.code();
    } catch (...) {
      return std::make_error_code(std::errc::io_error);
    }
#endif
  }
};
