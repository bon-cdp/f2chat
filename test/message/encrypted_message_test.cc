// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#include "lib/message/encrypted_message.h"

#include <memory>
#include <string>
#include <vector>

#include "absl/time/time.h"
#include "gtest/gtest.h"

namespace f2chat {
namespace {

// ===== Signature Tests =====

TEST(SignatureTest, CreateFromBytes) {
  std::vector<uint8_t> bytes(Signature::kSignatureSize, 0xAA);
  Signature sig(bytes);

  EXPECT_EQ(sig.bytes().size(), Signature::kSignatureSize);
  EXPECT_EQ(sig.bytes()[0], 0xAA);
}

TEST(SignatureTest, ToHexString) {
  std::vector<uint8_t> bytes(Signature::kSignatureSize, 0xFF);
  Signature sig(bytes);

  std::string hex = sig.ToHexString();
  EXPECT_EQ(hex.size(), Signature::kSignatureSize * 2);

  // All bytes are 0xFF, so hex should be all 'ff'
  for (size_t i = 0; i < hex.size(); i += 2) {
    EXPECT_EQ(hex.substr(i, 2), "ff");
  }
}

TEST(SignatureTest, FromHexString) {
  std::string hex(Signature::kSignatureSize * 2, 'a');  // All 'a' -> 0xAA
  auto sig_or = Signature::FromHexString(hex);

  ASSERT_TRUE(sig_or.ok());
  auto sig = sig_or.value();

  EXPECT_EQ(sig.bytes().size(), Signature::kSignatureSize);
  EXPECT_EQ(sig.bytes()[0], 0xAA);
}

TEST(SignatureTest, FromInvalidHexString) {
  std::string hex = "invalid";  // Too short
  auto sig_or = Signature::FromHexString(hex);

  EXPECT_FALSE(sig_or.ok());
}

TEST(SignatureTest, VerifyPlaceholder) {
  std::vector<uint8_t> bytes(Signature::kSignatureSize, 0);
  Signature sig(bytes);

  std::vector<uint8_t> message = {1, 2, 3, 4, 5};
  std::vector<uint8_t> public_key(32, 0);

  // Placeholder verification always returns true (for MVP)
  EXPECT_TRUE(sig.Verify(message, public_key));
}

// ===== MessageMetadata Tests =====

TEST(MessageMetadataTest, DefaultConstruction) {
  MessageMetadata metadata;
  metadata.message_id = "msg_001";
  metadata.sender_id = "alice";
  metadata.recipient_id = "bob";
  metadata.timestamp = absl::Now();
  metadata.scheme = "BGV";
  metadata.security_level = 128;

  EXPECT_EQ(metadata.message_id, "msg_001");
  EXPECT_EQ(metadata.sender_id, "alice");
  EXPECT_EQ(metadata.recipient_id, "bob");
  EXPECT_EQ(metadata.scheme, "BGV");
  EXPECT_EQ(metadata.security_level, 128);
}

// ===== EncryptedMessage Tests =====

TEST(EncryptedMessageTest, CreateWithValidInputs) {
  // Create placeholder ciphertext (OpenFHE requires actual context)
  lbcrypto::Ciphertext ciphertext = nullptr;  // Placeholder for test

  std::vector<uint8_t> sig_bytes(Signature::kSignatureSize, 0xBB);
  Signature signature(sig_bytes);

  MessageMetadata metadata;
  metadata.message_id = "msg_001";
  metadata.sender_id = "alice";
  metadata.recipient_id = "bob";
  metadata.timestamp = absl::Now();

  // Note: This will fail because ciphertext is null
  // In real tests, we'd use FheContext to create valid ciphertext
  auto msg_or = EncryptedMessage::Create(ciphertext, signature, metadata);
  EXPECT_FALSE(msg_or.ok());  // Fails due to null ciphertext
}

TEST(EncryptedMessageTest, CreateWithEmptyMessageId) {
  lbcrypto::Ciphertext ciphertext = nullptr;
  std::vector<uint8_t> sig_bytes(Signature::kSignatureSize, 0);
  Signature signature(sig_bytes);

  MessageMetadata metadata;
  metadata.message_id = "";  // Empty
  metadata.sender_id = "alice";
  metadata.recipient_id = "bob";

  auto msg_or = EncryptedMessage::Create(ciphertext, signature, metadata);
  EXPECT_FALSE(msg_or.ok());
  EXPECT_EQ(msg_or.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST(EncryptedMessageTest, CreateWithEmptySenderId) {
  lbcrypto::Ciphertext ciphertext = nullptr;
  std::vector<uint8_t> sig_bytes(Signature::kSignatureSize, 0);
  Signature signature(sig_bytes);

  MessageMetadata metadata;
  metadata.message_id = "msg_001";
  metadata.sender_id = "";  // Empty
  metadata.recipient_id = "bob";

  auto msg_or = EncryptedMessage::Create(ciphertext, signature, metadata);
  EXPECT_FALSE(msg_or.ok());
}

// ===== Signing Utilities Tests =====

TEST(SigningUtilitiesTest, GenerateSigningKeyPair) {
  auto keypair_or = GenerateSigningKeyPair();
  ASSERT_TRUE(keypair_or.ok());

  auto [public_key, private_key] = keypair_or.value();
  EXPECT_EQ(public_key.size(), 32);   // Ed25519 public key size
  EXPECT_EQ(private_key.size(), 32);  // Ed25519 private key size
}

TEST(SigningUtilitiesTest, SignMessage) {
  std::vector<uint8_t> message = {1, 2, 3, 4, 5};
  std::vector<uint8_t> private_key(32, 0xCC);

  auto sig_or = SignMessage(message, private_key);
  ASSERT_TRUE(sig_or.ok());

  auto signature = sig_or.value();
  EXPECT_EQ(signature.bytes().size(), Signature::kSignatureSize);
}

}  // namespace
}  // namespace f2chat
