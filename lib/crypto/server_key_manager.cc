// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#include "lib/crypto/server_key_manager.h"

#include <cstdint>
#include <memory>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "lib/crypto/fhe_context.h"

// OpenFHE includes
#include "openfhe.h"

namespace f2chat {

// ===== ServerKeyManager Implementation =====

ServerKeyManager::ServerKeyManager(const FheContext& context,
                                   PublicKey public_key,
                                   SecretKey private_key,
                                   KeyPair keypair)
    : context_(&context),
      public_key_(std::move(public_key)),
      private_key_(std::move(private_key)),
      keypair_(std::move(keypair)) {}

ServerKeyManager::~ServerKeyManager() = default;

absl::StatusOr<std::unique_ptr<ServerKeyManager>> ServerKeyManager::CreateNew(
    const FheContext& context) {
  // Generate new keypair using FheContext
  auto keypair_or = context.GenerateKeys();
  if (!keypair_or.ok()) {
    return keypair_or.status();
  }
  auto keypair = std::move(keypair_or).value();

  // Validate keypair
  if (!keypair.public_key || !keypair.private_key) {
    return absl::InternalError("Generated keypair has null keys");
  }

  // Wrap keys in our PublicKey/SecretKey types
  auto public_key = PublicKey(keypair.public_key);
  auto private_key = SecretKey(keypair.private_key);

  return std::unique_ptr<ServerKeyManager>(
      new ServerKeyManager(context, std::move(public_key),
                           std::move(private_key), std::move(keypair)));
}

absl::StatusOr<std::unique_ptr<ServerKeyManager>> ServerKeyManager::LoadFromBytes(
    const FheContext& context,
    const std::vector<uint8_t>& public_key_bytes,
    const std::vector<uint8_t>& private_key_bytes) {
  // TODO: Implement key deserialization
  // This requires OpenFHE's serialization API (lbcrypto::Serial)
  // For MVP, return Unimplemented
  (void)context;
  (void)public_key_bytes;
  (void)private_key_bytes;

  return absl::UnimplementedError(
      "LoadFromBytes not yet implemented (requires OpenFHE serialization)");
}

absl::StatusOr<std::vector<uint8_t>> ServerKeyManager::SerializePublicKey() const {
  // TODO: Implement public key serialization
  // For MVP, return placeholder
  return absl::UnimplementedError(
      "SerializePublicKey not yet implemented");
}

absl::StatusOr<std::vector<uint8_t>> ServerKeyManager::SerializePrivateKey() const {
  // TODO: Implement private key serialization
  // WARNING: This should be encrypted before storage
  return absl::UnimplementedError(
      "SerializePrivateKey not yet implemented");
}

absl::StatusOr<lbcrypto::Ciphertext> ServerKeyManager::EncryptHash(
    int64_t hash) const {
  if (!context_) {
    return absl::InternalError("Context is null");
  }

  // Encrypt single hash value
  // For SIMD batching, we put the hash in slot 0 and pad with zeros
  std::vector<int64_t> plaintext(context_->slot_count(), 0);
  plaintext[0] = hash;

  // Use FheContext to encrypt
  auto ciphertext_or = context_->EncryptVector(plaintext, public_key_);
  if (!ciphertext_or.ok()) {
    return ciphertext_or.status();
  }

  return ciphertext_or.value();
}

absl::StatusOr<int64_t> ServerKeyManager::DecryptCount(
    const lbcrypto::Ciphertext& count_ciphertext) const {
  if (!context_) {
    return absl::InternalError("Context is null");
  }

  if (!count_ciphertext) {
    return absl::InvalidArgumentError("Count ciphertext is null");
  }

  // Decrypt ciphertext to get vector of values
  auto plaintext_vector_or = context_->DecryptVector(count_ciphertext,
                                                      private_key_);
  if (!plaintext_vector_or.ok()) {
    return plaintext_vector_or.status();
  }

  const auto& plaintext = plaintext_vector_or.value();
  if (plaintext.empty()) {
    return absl::InternalError("Decrypted plaintext is empty");
  }

  // After EvalSumAllSlots, the count is in slot 0
  int64_t count = plaintext[0];

  return count;
}

}  // namespace f2chat
