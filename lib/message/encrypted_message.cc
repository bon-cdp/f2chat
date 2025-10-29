// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#include "lib/message/encrypted_message.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/time/time.h"

// OpenFHE includes
#include "openfhe.h"

// For Ed25519 signing, we'll use a simple stub for now
// TODO: Integrate with libsodium or OpenSSL for production
// For MVP, we'll use placeholder signatures

namespace f2chat {

// ===== Signature Implementation =====

Signature::Signature(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {
  if (bytes_.size() != kSignatureSize) {
    bytes_.resize(kSignatureSize, 0);
  }
}

absl::StatusOr<Signature> Signature::FromHexString(const std::string& hex) {
  if (hex.size() != kSignatureSize * 2) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid hex string length: ", hex.size(),
                     " (expected ", kSignatureSize * 2, ")"));
  }

  std::vector<uint8_t> bytes;
  bytes.reserve(kSignatureSize);

  for (size_t i = 0; i < hex.size(); i += 2) {
    std::string byte_str = hex.substr(i, 2);
    uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
    bytes.push_back(byte);
  }

  return Signature(std::move(bytes));
}

std::string Signature::ToHexString() const {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (uint8_t byte : bytes_) {
    oss << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

bool Signature::Verify(const std::vector<uint8_t>& message,
                       const std::vector<uint8_t>& public_key) const {
  // TODO: Implement Ed25519 verification using libsodium
  // For MVP, accept all signatures (placeholder)
  // This is NOT secure for production!
  (void)message;
  (void)public_key;
  return true;
}

// ===== EncryptedMessage Implementation =====

EncryptedMessage::EncryptedMessage(lbcrypto::Ciphertext ciphertext,
                                   Signature signature,
                                   MessageMetadata metadata)
    : ciphertext_(std::move(ciphertext)),
      signature_(std::move(signature)),
      metadata_(std::move(metadata)) {}

EncryptedMessage::~EncryptedMessage() = default;

absl::StatusOr<std::unique_ptr<EncryptedMessage>> EncryptedMessage::Create(
    lbcrypto::Ciphertext ciphertext,
    Signature signature,
    MessageMetadata metadata) {
  if (!ciphertext) {
    return absl::InvalidArgumentError("Ciphertext is null");
  }

  if (metadata.message_id.empty()) {
    return absl::InvalidArgumentError("Message ID is empty");
  }

  if (metadata.sender_id.empty()) {
    return absl::InvalidArgumentError("Sender ID is empty");
  }

  if (metadata.recipient_id.empty()) {
    return absl::InvalidArgumentError("Recipient ID is empty");
  }

  // Estimate ciphertext size (placeholder - actual size depends on serialization)
  metadata.ciphertext_size = 1024 * 100;  // ~100KB typical for BGV

  return std::unique_ptr<EncryptedMessage>(
      new EncryptedMessage(std::move(ciphertext), std::move(signature),
                           std::move(metadata)));
}

absl::StatusOr<std::vector<uint8_t>> EncryptedMessage::SerializeToBytes() const {
  // TODO: Implement proper serialization
  // For MVP, return placeholder
  // Production should use Protobuf or similar
  std::vector<uint8_t> serialized;

  // Placeholder format:
  // [metadata_size (4 bytes) | metadata | ciphertext | signature (64 bytes)]

  // For now, just include signature
  const auto& sig_bytes = signature_.bytes();
  serialized.insert(serialized.end(), sig_bytes.begin(), sig_bytes.end());

  return serialized;
}

absl::StatusOr<std::unique_ptr<EncryptedMessage>> EncryptedMessage::ParseFromBytes(
    const std::vector<uint8_t>& bytes) {
  // TODO: Implement proper deserialization
  // For MVP, return error
  (void)bytes;
  return absl::UnimplementedError(
      "Deserialization not yet implemented (requires Protobuf integration)");
}

size_t EncryptedMessage::EstimatedSizeBytes() const {
  return metadata_.ciphertext_size + Signature::kSignatureSize + 1024;
}

bool EncryptedMessage::VerifySignature(
    const std::vector<uint8_t>& sender_public_key) const {
  // TODO: Implement signature verification
  // For MVP, use signature's Verify method
  std::vector<uint8_t> message_bytes;  // Placeholder
  return signature_.Verify(message_bytes, sender_public_key);
}

// ===== Signing Utilities =====

absl::StatusOr<f2chat::Signature> SignMessage(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& private_key) {
  // TODO: Implement Ed25519 signing using libsodium
  // For MVP, return placeholder signature
  (void)message;
  (void)private_key;

  std::vector<uint8_t> signature_bytes(f2chat::Signature::kSignatureSize, 0xAA);
  return f2chat::Signature(std::move(signature_bytes));
}

absl::StatusOr<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
GenerateSigningKeyPair() {
  // TODO: Implement Ed25519 key generation using libsodium
  // For MVP, return placeholder keys
  std::vector<uint8_t> public_key(32, 0xBB);
  std::vector<uint8_t> private_key(32, 0xCC);
  return std::make_pair(std::move(public_key), std::move(private_key));
}

}  // namespace f2chat
