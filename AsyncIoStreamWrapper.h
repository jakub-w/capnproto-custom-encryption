#pragma once

#include <kj/async-io.h>

#include "IoStream.h"

// This class exists because kj::AsyncIoStream::read(void*, size_t) returns
// kj::Promise<void> and we need kj::Promise<size_t> to satisfy the return
// type of kj::AsyncIoStream::tryRead(), which is kj::Promise<size_t>, and
// it's the base class of EncryptedConnection.
// FIXME: It may be that it's an unnecessary complication but I don't
//        yet understand the library enough to make it better.
class AsyncIoStreamWrapper final : public IoStream<AsyncIoStreamWrapper> {
  kj::AsyncIoStream* inner_;

 public:
  AsyncIoStreamWrapper(kj::AsyncIoStream* stream) : inner_{stream} {}

  inline writeResult write(const void* buffer, size_t size) {
    inner_->write(buffer, size);
    return size;
  }

  inline readResult read(void* buffer, size_t size) {
    // return inner_->tryRead(buffer, size, size);
    inner_->read(buffer, size, size)
        .then([this, buffer, size](size_t bytes){
                std::cout << "read: ";
                print_hex(static_cast<const kj::byte*>(buffer),
                          static_cast<const kj::byte*>(buffer) + size);
                if (bytes < size) {
                  read(static_cast<kj::byte*>(buffer) + bytes,
                       size - bytes);
                }
              });
    // FIXME: Evaluate the promise and return actual bytes read.
    //        This is crucial because the promise for reading in
    //        EncryptedConnection could return first, reporting that something
    //        was read already when that's not the case.
    //        eagerlyEvaluate() doesn't really work for that all the time.
    //        Maybe pass waitScope in the constructor?
    return size;
  }

  inline void close() {
    inner_->shutdownWrite();
  }

 // private:
 //  kj::Promise<size_t> readInternal(void* buffer, size_t size) {
 //    return inner_->tryRead(buffer, 0, size).then(
 //        [size, buffer](size_t bytes_read){
 //          if (bytes_read < size) {
 //            return readInternal(buffer + bytes_read, size - bytes_read);
 //          }
 //          return kj::Promise<size_t>(10);
 //        });
 //  }
};

// TODO: wrap inner_->read() and inner_->write() in try-catch blocks
