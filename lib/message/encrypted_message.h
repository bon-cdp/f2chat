// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#ifndef F2CHAT_LIB_MESSAGE_ENCRYPTED_MESSAGE_H_
#define F2CHAT_LIB_MESSAGE_ENCRYPTED_MESSAGE_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"

// Forward declarations
namespace lbcrypto {
template <typename T> class CiphertextImpl;
class DCRTPoly;
using Ciphertext = std::shared_ptr<CiphertextImpl<DCRTPoly>>;
}  // namespace lbcrypto

namespace f2chat {

// ===== Message Metadata =====

// Metadata for an encrypted message.
// This is NOT encrypted (needed for routing and ordering).
//
// Google C++ Style: Simple struct for passive data.
struct MessageMetadata {
  // Unique message identifier
  std::string message_id;

  // Sender user ID
  std::string sender_id;

  // Recipient user ID
  std::string recipient_id;

  // Timestamp when message was created (client time)
  absl::Time timestamp;

  // Ciphertext size in bytes (for bandwidth tracking)
  size_t ciphertext_size = 0;

  // FHE scheme used (for versioning)
  std::string scheme = "BGV";

  // Security level in bits
  int security_level = 128;
};

// ===== Digital Signature =====

// Digital signature for message authenticity and integrity.
// Uses Ed25519 (industry standard, fast, secure).
//
// Google C++ Style: Wrapper class for type safety.
class Signature {
 public:
  // Signature size (Ed25519 standard)
  static constexpr size_t kSignatureSize = 64;

  // Create from raw bytes
  explicit Signature(std::vector<uint8_t> bytes);

  // Create from hex string
  static absl::StatusOr<Signature> FromHexString(const std::string& hex);

  // Access signature bytes
  const std::vector<uint8_t>& bytes() const { return bytes_; }

  // Convert to hex string (for serialization)
  std::string ToHexString() const;

  // Verify signature
  // Args:
  //   message: Data that was signed
  //   public_key: Ed25519 public key (32 bytes)
  // Returns:
  //   true if signature is valid, false otherwise
  bool Verify(const std::vector<uint8_t>& message,
              const std::vector<uint8_t>& public_key) const;

 private:
  std::vector<uint8_t> bytes_;
};

// ===== Encrypted Message =====

// Represents an encrypted message in the f2chat protocol.
//
// Components:
// - Ciphertext: FHE-encrypted message content (never exposed in plaintext)
// - Signature: Ed25519 signature for authenticity/integrity
// - Metadata: Routing info (sender, recipient, timestamp)
//
// Wire format (for network transmission):
//   [metadata | ciphertext | signature]
//
// Security properties:
// - Confidentiality: FHE encryption (server cannot read content)
// - Integrity: Digital signature (tampering detected)
// - Authenticity: Signature proves sender identity
//
// Google C++ Style: Clear ownership semantics, immutable after construction.
//
// Example usage:
//   auto msg_or = EncryptedMessage::Create(ciphertext, signature, metadata);
//   auto serialized = msg_or->SerializeToBytes();
//   // ... send over network ...
//   auto msg_or = EncryptedMessage::ParseFromBytes(serialized);
//
class EncryptedMessage {
 public:
  // Factory method (Google C++ Style: prefer factory over constructor)
  static absl::StatusOr<std::unique_ptr<EncryptedMessage>> Create(
      lbcrypto::Ciphertext ciphertext,
      Signature signature,
      MessageMetadata metadata);

  // Parse from serialized bytes (network transport)
  static absl::StatusOr<std::unique_ptr<EncryptedMessage>> ParseFromBytes(
      const std::vector<uint8_t>& bytes);

  // Destructor
  ~EncryptedMessage();

  // Delete copy (Google C++ Style: explicit about ownership)
  EncryptedMessage(const EncryptedMessage&) = delete;
  EncryptedMessage& operator=(const EncryptedMessage&) = delete;

  // Allow move
  EncryptedMessage(EncryptedMessage&&) noexcept = default;
  EncryptedMessage& operator=(EncryptedMessage&&) noexcept = default;

  // ===== Accessors =====

  const lbcrypto::Ciphertext& ciphertext() const { return ciphertext_; }
  const Signature& signature() const { return signature_; }
  const MessageMetadata& metadata() const { return metadata_; }

  const std::string& message_id() const { return metadata_.message_id; }
  const std::string& sender_id() const { return metadata_.sender_id; }
  const std::string& recipient_id() const { return metadata_.recipient_id; }
  absl::Time timestamp() const { return metadata_.timestamp; }

  // ===== Serialization =====

  // Serialize to bytes (for network transport)
  // Wire format: [metadata_size | metadata | ciphertext | signature]
  absl::StatusOr<std::vector<uint8_t>> SerializeToBytes() const;

  // Get estimated size in bytes
  size_t EstimatedSizeBytes() const;

  // ===== Verification =====

  // Verify signature (authenticity check)
  // Args:
  //   public_key: Sender's Ed25519 public key (32 bytes)
  // Returns:
  //   true if signature is valid, false otherwise
  bool VerifySignature(const std::vector<uint8_t>& sender_public_key) const;

 private:
  // Private constructor (use Create() factory)
  EncryptedMessage(lbcrypto::Ciphertext ciphertext,
                   Signature signature,
                   MessageMetadata metadata);

  // FHE ciphertext (encrypted message content)
  lbcrypto::Ciphertext ciphertext_;

  // Digital signature (Ed25519)
  Signature signature_;

  // Metadata (routing, timestamp, etc.)
  MessageMetadata metadata_;
};

// ===== Signing Utilities =====

// Sign a message with Ed25519 private key.
// Args:
//   message: Data to sign (typically serialized ciphertext + metadata)
//   private_key: Ed25519 private key (32 bytes)
// Returns:
//   Signature (64 bytes)
absl::StatusOr<Signature> SignMessage(
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& private_key);

// Generate Ed25519 key pair for signing.
// Returns:
//   {public_key (32 bytes), private_key (32 bytes)}
absl::StatusOr<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
GenerateSigningKeyPair();

}  // namespace f2chat

#endif  // F2CHAT_LIB_MESSAGE_ENCRYPTED_MESSAGE_H_
