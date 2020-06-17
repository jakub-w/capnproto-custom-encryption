#include <gtest/gtest.h>

#include <any>

#include "../EncryptionCommon.h"
#include "test_util.h"

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
      "works is incorrect on this system and the encryption will be borked.";
}

TEST(REPEAT_EncryptionCommon, ZKP) {
  EcScalar privkey;
  EcPoint pubkey;

  crypto_core_ristretto255_scalar_random(privkey.data());
  crypto_scalarmult_ristretto255_base(pubkey.data(), privkey.data());

  auto zkp = make_zkp("id", privkey, pubkey, basepoint);

  EcPoint random_point;
  crypto_core_ristretto255_random(random_point.data());

  EXPECT_EQ(zkp.user_id, "id");
  EXPECT_FALSE(is_all_zeros(zkp.V));
  EXPECT_FALSE(is_all_zeros(zkp.r));
  EXPECT_FALSE(check_zkp(zkp, pubkey, "id", "id", basepoint))
      << "Passes on bad id";
  EXPECT_TRUE(check_zkp(zkp, pubkey, "id", "another_id", basepoint))
      << "Fails on good id";
  EXPECT_FALSE(check_zkp(zkp, random_point, "id", "another_id", basepoint))
      << "Passes on wrong public key";
  EXPECT_FALSE(check_zkp(zkp, pubkey, "id", "another_id", random_point))
      << "Passes on wrong generator";
}

TEST(REPEAT_EncryptionCommon, make_key_confirmation_key) {
  EcPoint key_material;
  crypto_core_ristretto255_random(key_material.data());

  EcPoint key = make_key_confirmation_key<key.size()>(key_material);
  EcPoint identical_key = make_key_confirmation_key<key.size()>(key_material);

  ASSERT_FALSE(is_all_zeros(key)) << "Resulting key is 0";
  EXPECT_NE(key_material, key);
  EXPECT_EQ(key, identical_key)
      << "Resulting key should be identical for the same input";
}

TEST(REPEAT_EncryptionCommon, make_key_confirmation) {
  EcPoint key_material;
  crypto_core_ristretto255_random(key_material.data());

  HmacKey key = make_key_confirmation_key<key.size()>(key_material);

  std::string peer1_id = "id1";
  std::string peer2_id = "id2";

  EcPoint peer1_pubkey1, peer1_pubkey2, peer2_pubkey1, peer2_pubkey2;
  crypto_core_ristretto255_random(peer1_pubkey1.data());
  crypto_core_ristretto255_random(peer1_pubkey2.data());
  crypto_core_ristretto255_random(peer2_pubkey1.data());
  crypto_core_ristretto255_random(peer2_pubkey2.data());

  HmacHash hash =
      make_key_confirmation(key,
                            peer1_id, peer1_pubkey1, peer1_pubkey2,
                            peer2_id, peer2_pubkey1, peer2_pubkey2);
  HmacHash identical_hash =
      make_key_confirmation(key,
                            peer1_id, peer1_pubkey1, peer1_pubkey2,
                            peer2_id, peer2_pubkey1, peer2_pubkey2);

  ASSERT_FALSE(is_all_zeros(hash)) << "Resulting hash is 0";

  EXPECT_EQ(std::search(hash.begin(), hash.end(),
                        key.begin(), key.end()),
            hash.end())
      << "Hash contains the key!";
  EXPECT_EQ(std::search(hash.begin(), hash.end(),
                        peer1_id.begin(), peer1_id.end()),
            hash.end())
      << "Hash contains peer1_id!";
  EXPECT_EQ(std::search(hash.begin(), hash.end(),
                        peer1_pubkey1.begin(), peer1_pubkey1.end()),
            hash.end())
      << "Hash contains peer1_pubkey1!";
  EXPECT_EQ(std::search(hash.begin(), hash.end(),
                        peer1_pubkey2.begin(), peer1_pubkey2.end()),
            hash.end())
      << "Hash contains peer1_pubkey2!";
  EXPECT_EQ(std::search(hash.begin(), hash.end(),
                        peer2_id.begin(), peer2_id.end()),
            hash.end())
      << "Hash contains peer2_id!";
  EXPECT_EQ(std::search(hash.begin(), hash.end(),
                        peer2_pubkey1.begin(), peer2_pubkey1.end()),
            hash.end())
      << "Hash contains peer2_pubkey1!";
  EXPECT_EQ(std::search(hash.begin(), hash.end(),
                        peer2_pubkey2.begin(), peer2_pubkey2.end()),
            hash.end())
      << "Hash contains peer2_pubkey2!";

  EXPECT_EQ(hash, identical_hash)
      << "Resulting hash should be identical for the same input";
}

TEST(EncryptonCommon, derive_keys) {
  std::array<byte, 16> key1 = {0};
  std::array<byte, 32> key2 = {0};

  EcPoint key_material;
  crypto_core_ristretto255_random(key_material.data());

  derive_keys(key_material, key1, key2);

  EXPECT_FALSE(is_all_zeros(key1));
  EXPECT_FALSE(is_all_zeros(key2));

  EXPECT_EQ(std::search(key2.begin(), key2.end(), key1.begin(), key1.end()),
            key2.end())
      << "key1 is a part of key2";
}
