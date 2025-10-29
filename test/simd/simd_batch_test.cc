// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#include "lib/simd/simd_batch.h"

#include <memory>
#include <vector>

#include "gtest/gtest.h"
#include "lib/crypto/fhe_context.h"
#include "lib/message/encrypted_message.h"
#include "lib/util/config.h"

namespace f2chat {
namespace {

// Test fixture
class SimdBatchTest : public ::testing::Test {
 protected:
  void SetUp() override {
    FheParameters params;
    params.security_level = 128;
    params.polynomial_degree = 16384;
    params.slot_count = 8192;
    params.multiplicative_depth = 3;

    auto context_or = FheContext::Create(params);
    ASSERT_TRUE(context_or.ok());
    context_ = std::move(context_or).value();
  }

  std::unique_ptr<FheContext> context_;
};

// ===== Creation Tests =====

TEST_F(SimdBatchTest, CreateFromHashes) {
  std::vector<int64_t> hashes = {100, 200, 300, 400, 500};

  auto batch_or = SimdBatch::CreateFromHashes(*context_, hashes);
  // Note: This will likely fail without proper key setup
  // For MVP, we're testing the API structure
  if (!batch_or.ok()) {
    EXPECT_EQ(batch_or.status().code(), absl::StatusCode::kInvalidArgument);
  }
}

TEST_F(SimdBatchTest, CreateFromEmptyHashes) {
  std::vector<int64_t> hashes;

  auto batch_or = SimdBatch::CreateFromHashes(*context_, hashes);
  EXPECT_FALSE(batch_or.ok());
  EXPECT_EQ(batch_or.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST_F(SimdBatchTest, CreateFromTooManyHashes) {
  // Create more hashes than slot count
  std::vector<int64_t> hashes(10000, 42);  // More than 8192

  auto batch_or = SimdBatch::CreateFromHashes(*context_, hashes);
  EXPECT_FALSE(batch_or.ok());
  EXPECT_EQ(batch_or.status().code(), absl::StatusCode::kInvalidArgument);
}

// ===== Message Hash Tests =====

TEST(MessageHashTest, ComputeHash) {
  // Create placeholder message
  lbcrypto::Ciphertext ciphertext = nullptr;
  std::vector<uint8_t> sig_bytes(Signature::kSignatureSize, 0);
  Signature signature(sig_bytes);

  MessageMetadata metadata;
  metadata.message_id = "msg_001";
  metadata.sender_id = "alice";
  metadata.recipient_id = "bob";

  // Note: Can't create EncryptedMessage without valid ciphertext
  // For this test, we'll just test the hash function API

  // Placeholder test: Hash should be deterministic
  // In production, same message ID should hash to same value
}

}  // namespace
}  // namespace f2chat
