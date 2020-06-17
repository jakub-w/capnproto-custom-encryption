#include <gtest/gtest.h>
#include <sodium.h>

#include "../SodiumCipherStream.h"
#include "test_util.h"

using namespace crypto;

TEST(SodiumEncryptionContext, initialization) {
  SodiumEncryptionContext ctx;
  std::array<byte, NA_SS_KEYBYTES> key;
  std::array<byte, NA_SS_HEADERBYTES> header;

  randombytes_buf(key.data(), key.size());

  byte plaintext[] = "Foo";
  std::array<byte, sizeof(plaintext) + NA_SS_ABYTES> ciphertext;

  EXPECT_FALSE(ctx.Initialized()) << "Before initialization";

  std::error_code ec;
  ec = ctx.Encrypt(plaintext, sizeof(plaintext),
                   ciphertext.data(), ciphertext.size());

  ASSERT_TRUE(ec) << "Trying to encrypt before initialization didn't return "
      "an error code";
  EXPECT_EQ(ec.value(), (int)std::errc::operation_not_permitted)
      << "Encryption before initialization";

  ASSERT_FALSE(
      ctx.Initialize(key.data(), key.size(), header.data(), header.size()))
      << "Returned an error code";

  ASSERT_TRUE(ctx.Initialized()) << "After initialization";

  ASSERT_FALSE(ctx.Encrypt(plaintext, sizeof(plaintext),
                           ciphertext.data(), ciphertext.size()))
      << "Returned an error code";

  ASSERT_FALSE(is_all_zeros(ciphertext));

  // After std::move tests
  SodiumEncryptionContext another_ctx{std::move(ctx)};

  EXPECT_FALSE(ctx.Initialized()) << "After moving from";

  ASSERT_TRUE(another_ctx.Initialized())
      << "After std::move from an initialized object";

  std::fill_n(ciphertext.data(), ciphertext.size(), 0);

  EXPECT_FALSE(another_ctx.Encrypt(plaintext, sizeof(plaintext),
                                   ciphertext.data(), ciphertext.size()))
      << "Should encrypt fine after std::move";

  ASSERT_FALSE(is_all_zeros(ciphertext)) << "After std::move and encrypt";

  // TODO: Test move assignment
  ctx = std::move(another_ctx);
}
