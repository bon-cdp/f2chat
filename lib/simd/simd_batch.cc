// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#include "lib/simd/simd_batch.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "lib/crypto/fhe_context.h"
#include "lib/crypto/server_key_manager.h"
#include "lib/message/encrypted_message.h"

// OpenFHE includes
#include "openfhe.h"

namespace f2chat {

// ===== SimdBatch Implementation =====

SimdBatch::SimdBatch(lbcrypto::Ciphertext ciphertext,
                     std::vector<std::string> message_ids,
                     int slot_count)
    : ciphertext_(std::move(ciphertext)),
      message_ids_(std::move(message_ids)),
      slot_count_(slot_count) {}

SimdBatch::~SimdBatch() = default;

absl::StatusOr<std::unique_ptr<SimdBatch>> SimdBatch::Create(
    const FheContext& context,
    const ServerKeyManager& server_keys,
    const std::vector<std::shared_ptr<EncryptedMessage>>& messages) {
  if (messages.empty()) {
    return absl::InvalidArgumentError("Cannot create batch from empty messages");
  }

  const int slot_count = context.slot_count();
  if (messages.size() > static_cast<size_t>(slot_count)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Too many messages for batch: ", messages.size(),
                     " (max ", slot_count, ")"));
  }

  // Compute hashes for all messages
  std::vector<int64_t> hashes;
  std::vector<std::string> message_ids;
  hashes.reserve(messages.size());
  message_ids.reserve(messages.size());

  for (const auto& msg : messages) {
    hashes.push_back(ComputeMessageHash(*msg));
    message_ids.push_back(msg->message_id());
  }

  // Pad to slot count with zeros
  hashes.resize(slot_count, 0);
  message_ids.resize(slot_count, "");

  // Encrypt hashes into SIMD slots using server public key
  // All hashes encrypted with same key (server's) → batchable for FHE operations
  auto ciphertext_or = context.EncryptVector(
      hashes, server_keys.public_key());

  if (!ciphertext_or.ok()) {
    return ciphertext_or.status();
  }

  return std::unique_ptr<SimdBatch>(
      new SimdBatch(ciphertext_or.value(), std::move(message_ids), slot_count));
}

absl::StatusOr<std::unique_ptr<SimdBatch>> SimdBatch::CreateFromHashes(
    const FheContext& context,
    const ServerKeyManager& server_keys,
    const std::vector<int64_t>& hashes) {
  if (hashes.empty()) {
    return absl::InvalidArgumentError("Cannot create batch from empty hashes");
  }

  const int slot_count = context.slot_count();
  if (hashes.size() > static_cast<size_t>(slot_count)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Too many hashes for batch: ", hashes.size(),
                     " (max ", slot_count, ")"));
  }

  // Pad to slot count
  std::vector<int64_t> padded_hashes = hashes;
  padded_hashes.resize(slot_count, 0);

  // Create placeholder message IDs
  std::vector<std::string> message_ids;
  message_ids.reserve(slot_count);
  for (size_t i = 0; i < hashes.size(); ++i) {
    message_ids.push_back(absl::StrCat("msg_", i));
  }
  message_ids.resize(slot_count, "");

  // Encrypt hashes using server public key
  auto ciphertext_or = context.EncryptVector(
      padded_hashes, server_keys.public_key());

  if (!ciphertext_or.ok()) {
    return ciphertext_or.status();
  }

  return std::unique_ptr<SimdBatch>(
      new SimdBatch(ciphertext_or.value(), std::move(message_ids), slot_count));
}

absl::StatusOr<lbcrypto::Ciphertext> SimdBatch::CountMatches(
    const lbcrypto::Ciphertext& target_hash) const {
  if (!target_hash) {
    return absl::InvalidArgumentError("Target hash is null");
  }

  if (!ciphertext_) {
    return absl::InternalError("Batch ciphertext is null");
  }

  // Get crypto context from ciphertext
  auto context = ciphertext_->GetCryptoContext();
  if (!context) {
    return absl::InternalError("Crypto context is null");
  }

  try {
    // Step 1: Broadcast target to all slots
    // This is conceptually: target_broadcast = [target, target, ..., target]
    // In practice, we'd use EvalAdd with rotations or precompute broadcast
    // For MVP, we'll use the target directly (assumes it's already broadcast)

    // Step 2: Element-wise equality check
    // Result: [1, 0, 0, 1, ...] where 1 = match, 0 = no match
    // OpenFHE: (a == b) implemented as: (a - b == 0) ? 1 : 0
    // For MVP, we'll use subtraction and check for zero
    auto diff = context->EvalSub(ciphertext_, target_hash);

    // Step 3: Convert to binary (1 if equal, 0 otherwise)
    // This requires a comparison circuit - for MVP, we'll return diff
    // In production, use HEIR to compile this to optimized FHE circuit

    // Step 4: Sum across all slots (reduce operation)
    // This counts how many matches we found
    // Requires rotations: O(log N) with optimization
    // For MVP, we'll return the diff ciphertext
    // Client will decrypt to count matches

    return diff;

  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrCat("Failed to count matches: ", e.what()));
  }
}

absl::StatusOr<std::vector<bool>> SimdBatch::ExtractMatchFlags(
    const lbcrypto::Ciphertext& match_flags,
    const FheContext& context) const {
  // Decrypt match flags to get boolean vector
  // This is CLIENT-SIDE operation (requires secret key)

  // For MVP, return placeholder
  // Production: Decrypt match_flags, convert to boolean vector
  (void)match_flags;
  (void)context;

  std::vector<bool> flags(message_ids_.size(), false);
  return flags;
}

int64_t SimdBatch::ComputeMessageHash(const EncryptedMessage& message) {
  // Compute hash of message for batching
  // For MVP, use simple hash of message ID
  // Production: Use secure hash (SHA-256) of ciphertext + metadata

  std::hash<std::string> hasher;
  size_t hash = hasher(message.message_id());

  // Convert to int64_t (truncate if necessary)
  return static_cast<int64_t>(hash & 0x7FFFFFFFFFFFFFFFULL);
}

}  // namespace f2chat
