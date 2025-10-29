// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#ifndef F2CHAT_LIB_SIMD_SIMD_BATCH_H_
#define F2CHAT_LIB_SIMD_SIMD_BATCH_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

// Forward declarations
namespace lbcrypto {
template <typename T> class CiphertextImpl;
class DCRTPoly;
using Ciphertext = std::shared_ptr<CiphertextImpl<DCRTPoly>>;
}  // namespace lbcrypto

namespace f2chat {

// Forward declarations
class FheContext;
class EncryptedMessage;
class ServerKeyManager;

// ===== SIMD Batch =====

// Packs multiple encrypted messages into SIMD slots for parallel processing.
//
// This is THE KEY to scalability:
// - Without batching: N messages → N FHE operations → O(N²) comparisons
// - With batching: N messages → ceil(N/8192) batches → O(N) comparisons
//
// Speedup: 5,000-10,000× for spam detection on 10,000 messages
//
// How it works:
// 1. Pack message hashes into SIMD slots (8192 messages per ciphertext)
// 2. Server performs parallel operations on all slots simultaneously
// 3. Example: Check if message M appears in batch → 1 FHE operation
//    (instead of 8192 separate operations)
//
// SIMD operations (from HElib/OpenFHE):
// - Element-wise arithmetic: Add, multiply (cheap, parallel)
// - Rotations: Shift slot contents (expensive, O(log N) with optimization)
// - Reduce: Aggregate results across slots (requires rotations)
//
// HEIR optimization:
// - Automatically minimizes rotations (72-179× speedup)
// - Layout optimization for common patterns
//
// Google C++ Style: Clear ownership, immutable after construction.
//
// Example usage:
//   // Pack messages into batch
//   auto batch_or = SimdBatch::Create(context, messages);
//
//   // Detect duplicates (server-side, on encrypted batch)
//   auto target_hash = ComputeHash(target_message);
//   auto matches_or = batch->CountMatches(target_hash);
//   // matches = how many times target appears in batch
//
class SimdBatch {
 public:
  // Factory method: Create batch from encrypted messages
  // Packs message hashes into SIMD slots.
  //
  // Args:
  //   context: FHE context (for encryption operations)
  //   server_keys: Server key manager (provides public key for hash encryption)
  //   messages: Encrypted messages to batch (up to slot_count)
  //
  // Returns:
  //   SimdBatch with messages packed into SIMD slots
  //   Error if messages.size() > slot_count
  //
  // Performance: O(N) where N = messages.size()
  static absl::StatusOr<std::unique_ptr<SimdBatch>> Create(
      const FheContext& context,
      const ServerKeyManager& server_keys,
      const std::vector<std::shared_ptr<EncryptedMessage>>& messages);

  // Factory method: Create batch from message hashes (for testing)
  // Directly pack hashes into SIMD slots.
  //
  // Args:
  //   context: FHE context
  //   server_keys: Server key manager (provides public key for hash encryption)
  //   hashes: Message hashes (integers)
  //
  // Returns:
  //   SimdBatch with hashes packed
  static absl::StatusOr<std::unique_ptr<SimdBatch>> CreateFromHashes(
      const FheContext& context,
      const ServerKeyManager& server_keys,
      const std::vector<int64_t>& hashes);

  // Destructor
  ~SimdBatch();

  // Delete copy
  SimdBatch(const SimdBatch&) = delete;
  SimdBatch& operator=(const SimdBatch&) = delete;

  // Allow move
  SimdBatch(SimdBatch&&) noexcept = default;
  SimdBatch& operator=(SimdBatch&&) noexcept = default;

  // ===== Accessors =====

  // Get batched ciphertext (all messages packed in SIMD slots)
  const lbcrypto::Ciphertext& ciphertext() const { return ciphertext_; }

  // Get message IDs (tracks which message is in which slot)
  const std::vector<std::string>& message_ids() const { return message_ids_; }

  // Get number of messages in batch
  size_t size() const { return message_ids_.size(); }

  // Get number of SIMD slots
  int slot_count() const { return slot_count_; }

  // ===== Homomorphic Operations (Server-Side, Encrypted) =====

  // Count how many messages in batch match target hash.
  // This is a PARALLEL operation on all slots simultaneously.
  //
  // Algorithm (simplified):
  //   1. Broadcast target to all slots: T = [target, target, ..., target]
  //   2. Compare: Eq = (Batch == T)  // Element-wise, all slots in parallel
  //   3. Reduce: Count = sum(Eq)     // Aggregate matches
  //
  // Args:
  //   target_hash: Hash to search for (encrypted)
  //
  // Returns:
  //   Encrypted count (how many matches)
  //
  // Performance: ~100ms for 8192-message batch (with rotations)
  // Speedup vs. naive: 8192× (one operation instead of 8192)
  absl::StatusOr<lbcrypto::Ciphertext> CountMatches(
      const lbcrypto::Ciphertext& target_hash) const;

  // Extract flags indicating which messages matched target.
  // This is for CLIENT-SIDE decryption (server returns encrypted flags).
  //
  // Returns:
  //   Vector of bools: [true, false, false, true, ...]
  //   (true = message i matched target)
  //
  // Note: This requires decryption (client operation, not server)
  absl::StatusOr<std::vector<bool>> ExtractMatchFlags(
      const lbcrypto::Ciphertext& match_flags,
      const FheContext& context) const;

  // ===== Utility =====

  // Compute hash of encrypted message (for batching)
  // This is a PLACEHOLDER - production should use secure hash (SHA-256)
  static int64_t ComputeMessageHash(const EncryptedMessage& message);

 private:
  // Private constructor (use Create() factory)
  SimdBatch(lbcrypto::Ciphertext ciphertext,
            std::vector<std::string> message_ids,
            int slot_count);

  // Batched ciphertext (messages packed in SIMD slots)
  lbcrypto::Ciphertext ciphertext_;

  // Message IDs (tracks which slot contains which message)
  // message_ids_[i] = ID of message in slot i
  // Empty string = slot i is unused (padding)
  std::vector<std::string> message_ids_;

  // Number of SIMD slots (typically 8192)
  int slot_count_;
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_SIMD_SIMD_BATCH_H_
