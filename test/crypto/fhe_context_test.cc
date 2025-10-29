// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#include "lib/crypto/fhe_context.h"

#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "lib/util/config.h"

namespace f2chat {
namespace {

// Test fixture for FheContext tests
class FheContextTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create default parameters for testing
    params_.security_level = 128;
    params_.polynomial_degree = 16384;
    params_.plaintext_modulus = 65537;
    params_.multiplicative_depth = 3;  // Lower for faster tests
    params_.slot_count = 8192;
    params_.key_switch_technique = FheParameters::KeySwitchTechnique::HYBRID;
  }

  FheParameters params_;
};

// ===== Creation Tests =====

TEST_F(FheContextTest, CreateWithValidParameters) {
  auto context_or = FheContext::Create(params_);
  ASSERT_TRUE(context_or.ok()) << context_or.status();

  auto context = std::move(context_or).value();
  EXPECT_NE(context, nullptr);
  EXPECT_EQ(context->slot_count(), 8192);
}

TEST_F(FheContextTest, CreateWithInvalidSecurityLevel) {
  params_.security_level = 64;  // Too low

  auto context_or = FheContext::Create(params_);
  EXPECT_FALSE(context_or.ok());
  EXPECT_EQ(context_or.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST_F(FheContextTest, CreateWithInvalidPolynomialDegree) {
  params_.polynomial_degree = 512;  // Too low

  auto context_or = FheContext::Create(params_);
  EXPECT_FALSE(context_or.ok());
}

TEST_F(FheContextTest, CreateWithMismatchedSlotCount) {
  params_.slot_count = 1000;  // Doesn't match polynomial_degree/2

  auto context_or = FheContext::Create(params_);
  EXPECT_FALSE(context_or.ok());
}

// ===== Key Generation Tests =====

TEST_F(FheContextTest, GenerateKeys) {
  auto context = FheContext::Create(params_).value();

  auto keypair_or = context->GenerateKeys();
  ASSERT_TRUE(keypair_or.ok()) << keypair_or.status();

  auto keypair = std::move(keypair_or).value();
  EXPECT_NE(keypair.public_key, nullptr);
  EXPECT_NE(keypair.private_key, nullptr);
}

// ===== Encryption/Decryption Tests =====

TEST_F(FheContextTest, EncryptDecryptString) {
  auto context = FheContext::Create(params_).value();
  auto keypair = context->GenerateKeys().value();

  std::string plaintext = "Hello, f2chat!";
  auto public_key = PublicKey(keypair.public_key);
  auto secret_key = SecretKey(keypair.private_key);

  // Encrypt
  auto ciphertext_or = context->Encrypt(plaintext, public_key);
  ASSERT_TRUE(ciphertext_or.ok()) << ciphertext_or.status();
  auto ciphertext = ciphertext_or.value();
  EXPECT_NE(ciphertext, nullptr);

  // Decrypt
  auto decrypted_or = context->Decrypt(ciphertext, secret_key);
  ASSERT_TRUE(decrypted_or.ok()) << decrypted_or.status();
  auto decrypted = decrypted_or.value();

  EXPECT_EQ(decrypted, plaintext);
}

TEST_F(FheContextTest, EncryptDecryptVector) {
  auto context = FheContext::Create(params_).value();
  auto keypair = context->GenerateKeys().value();

  std::vector<int64_t> plaintext = {1, 2, 3, 4, 5, 100, 255};
  auto public_key = PublicKey(keypair.public_key);
  auto secret_key = SecretKey(keypair.private_key);

  // Encrypt
  auto ciphertext_or = context->EncryptVector(plaintext, public_key);
  ASSERT_TRUE(ciphertext_or.ok());
  auto ciphertext = ciphertext_or.value();

  // Decrypt
  auto decrypted_or = context->DecryptVector(ciphertext, secret_key);
  ASSERT_TRUE(decrypted_or.ok());
  auto decrypted = decrypted_or.value();

  // Check first few values (rest are padding)
  for (size_t i = 0; i < plaintext.size(); ++i) {
    EXPECT_EQ(decrypted[i], plaintext[i]) << "Mismatch at index " << i;
  }
}

TEST_F(FheContextTest, EncryptEmptyString) {
  auto context = FheContext::Create(params_).value();
  auto keypair = context->GenerateKeys().value();

  std::string plaintext = "";
  auto public_key = PublicKey(keypair.public_key);
  auto secret_key = SecretKey(keypair.private_key);

  auto ciphertext_or = context->Encrypt(plaintext, public_key);
  ASSERT_TRUE(ciphertext_or.ok());

  auto decrypted_or = context->Decrypt(ciphertext_or.value(), secret_key);
  ASSERT_TRUE(decrypted_or.ok());
  EXPECT_EQ(decrypted_or.value(), plaintext);
}

TEST_F(FheContextTest, EncryptVectorTooLarge) {
  auto context = FheContext::Create(params_).value();
  auto keypair = context->GenerateKeys().value();

  // Create vector larger than slot count
  std::vector<int64_t> plaintext(params_.slot_count + 100, 42);
  auto public_key = PublicKey(keypair.public_key);

  auto ciphertext_or = context->EncryptVector(plaintext, public_key);
  EXPECT_FALSE(ciphertext_or.ok());
  EXPECT_EQ(ciphertext_or.status().code(), absl::StatusCode::kInvalidArgument);
}

// ===== SIMD Batching Tests =====

TEST_F(FheContextTest, SimdBatching) {
  auto context = FheContext::Create(params_).value();
  auto keypair = context->GenerateKeys().value();

  // Pack multiple values into SIMD slots
  std::vector<int64_t> values = {10, 20, 30, 40, 50};
  auto public_key = PublicKey(keypair.public_key);
  auto secret_key = SecretKey(keypair.private_key);

  auto ciphertext_or = context->EncryptVector(values, public_key);
  ASSERT_TRUE(ciphertext_or.ok());

  auto decrypted_or = context->DecryptVector(ciphertext_or.value(), secret_key);
  ASSERT_TRUE(decrypted_or.ok());
  auto decrypted = decrypted_or.value();

  // Verify all values
  for (size_t i = 0; i < values.size(); ++i) {
    EXPECT_EQ(decrypted[i], values[i]);
  }

  // Rest should be padding (zeros)
  for (size_t i = values.size(); i < 100; ++i) {
    EXPECT_EQ(decrypted[i], 0);
  }
}

TEST_F(FheContextTest, FullSlotUtilization) {
  auto context = FheContext::Create(params_).value();
  auto keypair = context->GenerateKeys().value();

  // Fill all slots
  std::vector<int64_t> values(params_.slot_count, 42);
  auto public_key = PublicKey(keypair.public_key);
  auto secret_key = SecretKey(keypair.private_key);

  auto ciphertext_or = context->EncryptVector(values, public_key);
  ASSERT_TRUE(ciphertext_or.ok());

  auto decrypted_or = context->DecryptVector(ciphertext_or.value(), secret_key);
  ASSERT_TRUE(decrypted_or.ok());
  auto decrypted = decrypted_or.value();

  // Verify all slots
  for (int i = 0; i < params_.slot_count; ++i) {
    EXPECT_EQ(decrypted[i], 42);
  }
}

}  // namespace
}  // namespace f2chat
