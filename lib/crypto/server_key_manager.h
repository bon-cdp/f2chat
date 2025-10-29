// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#ifndef F2CHAT_LIB_CRYPTO_SERVER_KEY_MANAGER_H_
#define F2CHAT_LIB_CRYPTO_SERVER_KEY_MANAGER_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "lib/crypto/fhe_context.h"

namespace f2chat {

// ===== Server Key Manager =====
//
// Manages the server's FHE keypair for spam detection.
//
// **Phase 1 (Current):** Single server keypair
//   - All clients encrypt message hashes with server's public key
//   - Server can decrypt spam counts (trusted server model)
//   - Simple, fast deployment
//
// **Phase 3 (Future):** Threshold keypair
//   - Global public key for encryption
//   - Secret key split into N shares (e.g., 5 shares, k=3 threshold)
//   - Each share deployed to different cloud provider (AWS, Google, Cloudflare, etc.)
//   - Requires k=3 providers to cooperate for decryption
//   - No single provider can decrypt alone
//
// Trust model (Phase 1):
//   - Server operator is trusted
//   - Server learns: Spam counts (e.g., "message X duplicated 5000 times")
//   - Server does NOT learn: Message content (still E2EE encrypted)
//   - Trade-off: Centralized trust for simpler deployment
//
// Privacy properties:
//   ✅ Message content: E2EE with recipient's key (server blind)
//   ✅ Message hashes: FHE-encrypted (server operates on ciphertexts)
//   ⚠️ Spam counts: Server can decrypt (Phase 1 limitation)
//   ✅ No censorship: Server cannot read/modify message content
//
// Example usage:
//   // Server setup
//   auto server_keys = ServerKeyManager::CreateNew(context).value();
//   auto server_pk = server_keys.public_key_bytes();  // Distribute to clients
//
//   // Client: Encrypt message hash
//   auto hash = ComputeMessageHash(message);
//   auto encrypted_hash = server_keys.EncryptHash(hash).value();
//
//   // Server: Batch and detect duplicates (FHE operations)
//   auto batch = SimdBatch::Create(context, messages, server_keys).value();
//   auto count_ct = batch->DetectDuplicates(target_hash).value();
//
//   // Server: Decrypt spam count
//   auto count = server_keys.DecryptCount(count_ct).value();
//   if (count > 1000) {
//     // Alert affected users: "Suspected spam campaign"
//   }
//
class ServerKeyManager {
 public:
  // Factory method: Generate new server keypair.
  //
  // This generates a fresh FHE keypair for spam detection.
  // The public key should be distributed to all clients (via HTTPS, etc.).
  // The private key must be kept secret on the server.
  //
  // Args:
  //   context: FHE context (provides cryptographic parameters)
  //
  // Returns:
  //   ServerKeyManager with newly generated keypair
  //
  // Performance: ~1-2 seconds (expensive, do once at server startup)
  //
  static absl::StatusOr<std::unique_ptr<ServerKeyManager>> CreateNew(
      const FheContext& context);

  // Factory method: Load existing keypair from serialized bytes.
  //
  // Used to restore server keypair after restart (load from disk/database).
  //
  // Args:
  //   context: FHE context
  //   public_key_bytes: Serialized public key
  //   private_key_bytes: Serialized private key
  //
  // Returns:
  //   ServerKeyManager with loaded keypair
  //
  static absl::StatusOr<std::unique_ptr<ServerKeyManager>> LoadFromBytes(
      const FheContext& context,
      const std::vector<uint8_t>& public_key_bytes,
      const std::vector<uint8_t>& private_key_bytes);

  // Destructor
  ~ServerKeyManager();

  // Delete copy (Google C++ Style: explicit ownership)
  ServerKeyManager(const ServerKeyManager&) = delete;
  ServerKeyManager& operator=(const ServerKeyManager&) = delete;

  // Allow move
  ServerKeyManager(ServerKeyManager&&) noexcept = default;
  ServerKeyManager& operator=(ServerKeyManager&&) noexcept = default;

  // ===== Key Access =====

  // Get public key (for client-side encryption).
  const PublicKey& public_key() const { return public_key_; }

  // Get private key (for server-side decryption).
  // CAUTION: This is sensitive! Should only be used server-side.
  const SecretKey& private_key() const { return private_key_; }

  // ===== Serialization =====

  // Serialize public key to bytes (for distribution to clients).
  //
  // Clients need the server's public key to encrypt message hashes.
  // This should be fetched over HTTPS during client initialization.
  //
  // Returns:
  //   Serialized public key (can be sent over network)
  //
  absl::StatusOr<std::vector<uint8_t>> SerializePublicKey() const;

  // Serialize private key to bytes (for server persistence).
  //
  // Server should save this to disk/database for restart recovery.
  // WARNING: Keep this secret! If leaked, spam detection privacy is lost.
  //
  // Returns:
  //   Serialized private key (MUST be encrypted before storing)
  //
  absl::StatusOr<std::vector<uint8_t>> SerializePrivateKey() const;

  // ===== Hash Encryption (Client-Side Operation) =====

  // Encrypt message hash with server's public key.
  //
  // This is what clients do before sending messages:
  //   1. Compute hash of message content
  //   2. Encrypt hash with server public key
  //   3. Send encrypted content (E2EE) + encrypted hash (FHE) to server
  //
  // Args:
  //   hash: Message hash (e.g., SHA-256 output truncated to 64 bits)
  //
  // Returns:
  //   FHE ciphertext containing encrypted hash
  //
  // Performance: ~50-100ms (client-side)
  //
  absl::StatusOr<lbcrypto::Ciphertext> EncryptHash(int64_t hash) const;

  // ===== Count Decryption (Server-Side Operation) =====

  // Decrypt spam count result.
  //
  // After FHE spam detection, server has encrypted count ciphertext.
  // This decrypts it to learn: "How many times did this message appear?"
  //
  // Args:
  //   count_ciphertext: Result from FheOperations::EvalSumAllSlots
  //
  // Returns:
  //   Plaintext count (number of duplicates found)
  //
  // Performance: ~50-100ms (server-side)
  //
  // Privacy note: Server learns the count, not the message content.
  //
  absl::StatusOr<int64_t> DecryptCount(
      const lbcrypto::Ciphertext& count_ciphertext) const;

  // ===== Future: Threshold Key Management (Phase 3) =====

  // TODO(Phase 3): Implement threshold key generation
  // Split private key into N shares using Shamir Secret Sharing
  // Each share can perform partial decryption
  // Combine k partial decryptions to recover plaintext
  //
  // Planned API:
  //   static ThresholdKeyManager::Generate(context, k, n);
  //   PartialDecryption ThresholdKeyManager::PartialDecrypt(ct, share_i);
  //   Plaintext ThresholdKeyManager::CombineShares(vector<PartialDecryption>);

 private:
  // Private constructor (use CreateNew or LoadFromBytes)
  ServerKeyManager(const FheContext& context,
                   PublicKey public_key,
                   SecretKey private_key,
                   KeyPair keypair);

  // FHE context (for encryption/decryption operations)
  const FheContext* context_;

  // Server's public key (distributed to clients)
  PublicKey public_key_;

  // Server's private key (kept secret on server)
  SecretKey private_key_;

  // Full keypair (includes evaluation keys for FHE operations)
  KeyPair keypair_;
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_CRYPTO_SERVER_KEY_MANAGER_H_
