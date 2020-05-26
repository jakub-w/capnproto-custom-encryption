#include <gtest/gtest.h>

#include "../EncryptionCommon.h"

TEST(EncryptonCommon, basepoint) {
  EcScalar input;
  EcScalar output1;
  EcScalar output2;

  crypto_scalarmult_ristretto255_base(output1.data(), input.data());
  crypto_scalarmult_ristretto255(output2.data(), input.data(),
                                 basepoint.data());

  ASSERT_TRUE(output1 == output2)
      << "This is a FATAL failure. Don't use this library it this fails!\n"
      << "This failure means that a fundamental assumption of how libsodium "
      "works is incorrect on this system and the encryption will be broken.";
}

TEST(EncryptionCommon, ZKP) {
  EcScalar privkey;
  EcPoint pubkey;

  crypto_core_ristretto255_scalar_random(privkey.data());
  crypto_scalarmult_ristretto255_base(pubkey.data(), privkey.data());

  auto zkp = make_zkp("id", privkey, pubkey, basepoint);

  EcPoint random_point;
  crypto_core_ristretto255_random(random_point.data());

  EXPECT_EQ(zkp.user_id, "id");
  EXPECT_TRUE(std::any_of(zkp.V.begin(), zkp.V.end(),
                          [](byte b){ return b != 0; }));
  EXPECT_TRUE(std::any_of(zkp.r.begin(), zkp.r.end(),
                          [](byte b){ return b != 0; }));
  EXPECT_FALSE(check_zkp(zkp, pubkey, "id", basepoint))
      << "Passes on bad id";
  EXPECT_TRUE(check_zkp(zkp, pubkey, "another_id", basepoint))
      << "Fails on good id";
  EXPECT_FALSE(check_zkp(zkp, random_point, "id", basepoint))
      << "Passes on wrong public key";
  EXPECT_FALSE(check_zkp(zkp, pubkey, "another_id", random_point))
      << "Passes on wrong generator";
}
