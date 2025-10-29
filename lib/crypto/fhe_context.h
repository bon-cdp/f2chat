// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#ifndef F2CHAT_LIB_CRYPTO_FHE_CONTEXT_H_
#define F2CHAT_LIB_CRYPTO_FHE_CONTEXT_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "lib/util/config.h"

// Forward declarations (OpenFHE types)
// This avoids exposing OpenFHE headers in our public API
namespace lbcrypto {
template <typename T> class CryptoContextImpl;
class DCRTPoly;
template <typename T> class KeyPair;
template <typename T> class PublicKeyImpl;
template <typename T> class PrivateKeyImpl;
template <typename T> class CiphertextImpl;
template <typename T> class EvalKeyImpl;

using CryptoContext = std::shared_ptr<CryptoContextImpl<DCRTPoly>>;
using KeyPairDCRTPoly = KeyPair<DCRTPoly>;
using PublicKey = std::shared_ptr<PublicKeyImpl<DCRTPoly>>;
using PrivateKey = std::shared_ptr<PrivateKeyImpl<DCRTPoly>>;
using Ciphertext = std::shared_ptr<CiphertextImpl<DCRTPoly>>;
using EvalKey = std::shared_ptr<EvalKeyImpl<DCRTPoly>>;
}  // namespace lbcrypto

namespace f2chat {

// ===== Key Pair =====

// Represents an FHE public/private key pair.
// Following Google C++ Style: Simple struct for data, no complex logic.
struct KeyPair {
  std::shared_ptr<lbcrypto::PublicKey> public_key;
  std::shared_ptr<lbcrypto::PrivateKey> private_key;

  // Evaluation keys (for homomorphic operations)
  // These are large (~100MB-1GB) and enable server-side FHE operations
  std::shared_ptr<lbcrypto::EvalKey> eval_key_mult;      // For multiplication
  std::shared_ptr<lbcrypto::EvalKey> eval_key_rotate;    // For rotations (SIMD)
};

// ===== Public Key (for encryption only) =====

// Wrapper around OpenFHE public key for type safety.
// Google C++ Style: Explicit type wrapper, prevents misuse.
class PublicKey {
 public:
  explicit PublicKey(std::shared_ptr<lbcrypto::PublicKey> key)
      : key_(std::move(key)) {}

  const std::shared_ptr<lbcrypto::PublicKey>& key() const { return key_; }

 private:
  std::shared_ptr<lbcrypto::PublicKey> key_;
};

// ===== Secret Key (for decryption only) =====

// Wrapper around OpenFHE private key.
// Google C++ Style: Clear ownership semantics with unique_ptr in practice,
// but OpenFHE uses shared_ptr internally.
class SecretKey {
 public:
  explicit SecretKey(std::shared_ptr<lbcrypto::PrivateKey> key)
      : key_(std::move(key)) {}

  const std::shared_ptr<lbcrypto::PrivateKey>& key() const { return key_; }

 private:
  std::shared_ptr<lbcrypto::PrivateKey> key_;
};

// ===== FHE Context =====

// Main cryptographic context for FHE operations.
//
// Responsibilities:
// - Initialize OpenFHE with BGV scheme
// - Generate key pairs (public, private, evaluation keys)
// - Encrypt plaintext → ciphertext
// - Decrypt ciphertext → plaintext
// - Manage cryptographic parameters
//
// Thread-safety: This class is NOT thread-safe. Create one context per thread
// or use external synchronization.
//
// Example usage:
//   auto params = FheParameters{};
//   auto context_or = FheContext::Create(params);
//   if (!context_or.ok()) { /* handle error */ }
//   auto context = std::move(context_or).value();
//
//   auto keypair_or = context->GenerateKeys();
//   auto ciphertext_or = context->Encrypt("hello", keypair_or->public_key);
//   auto plaintext_or = context->Decrypt(ciphertext_or.value(), keypair_or->private_key);
//
class FheContext {
 public:
  // Factory method (Google C++ Style: prefer factory over constructor)
  // Returns error status if parameters are invalid or OpenFHE initialization fails.
  static absl::StatusOr<std::unique_ptr<FheContext>> Create(
      const FheParameters& params);

  // Destructor (rule of 5: if you define one, define all or delete)
  ~FheContext();

  // Delete copy constructor and assignment (Google C++ Style: explicit about ownership)
  FheContext(const FheContext&) = delete;
  FheContext& operator=(const FheContext&) = delete;

  // Allow move operations (transfer ownership)
  FheContext(FheContext&&) noexcept = default;
  FheContext& operator=(FheContext&&) noexcept = default;

  // ===== Key Generation =====

  // Generate a new key pair (public, private, evaluation keys).
  // This is expensive (~seconds) and should be done once per user.
  //
  // Returns:
  //   KeyPair containing public key, private key, and evaluation keys
  //   Error status if key generation fails
  absl::StatusOr<KeyPair> GenerateKeys() const;

  // ===== Encryption =====

  // Encrypt plaintext string into FHE ciphertext.
  //
  // Args:
  //   plaintext: String to encrypt (will be encoded as integers)
  //   public_key: Public key for encryption
  //
  // Returns:
  //   Ciphertext (opaque handle to OpenFHE ciphertext)
  //   Error status if encryption fails
  //
  // Performance: ~50-100ms for typical message
  absl::StatusOr<std::shared_ptr<lbcrypto::Ciphertext>> Encrypt(
      const std::string& plaintext,
      const PublicKey& public_key) const;

  // Encrypt vector of integers (for SIMD batching).
  // This packs multiple values into SIMD slots.
  //
  // Args:
  //   plaintext: Vector of integers (length ≤ slot_count)
  //   public_key: Public key for encryption
  //
  // Returns:
  //   Ciphertext with values packed in SIMD slots
  absl::StatusOr<std::shared_ptr<lbcrypto::Ciphertext>> EncryptVector(
      const std::vector<int64_t>& plaintext,
      const PublicKey& public_key) const;

  // ===== Decryption =====

  // Decrypt FHE ciphertext into plaintext string.
  //
  // Args:
  //   ciphertext: Ciphertext to decrypt
  //   secret_key: Secret key for decryption
  //
  // Returns:
  //   Decrypted plaintext string
  //   Error status if decryption fails (e.g., noise overflow)
  //
  // Performance: ~50-100ms
  absl::StatusOr<std::string> Decrypt(
      const std::shared_ptr<lbcrypto::Ciphertext>& ciphertext,
      const SecretKey& secret_key) const;

  // Decrypt to vector of integers (for SIMD batching).
  //
  // Returns:
  //   Vector of decrypted integers (length = slot_count)
  absl::StatusOr<std::vector<int64_t>> DecryptVector(
      const std::shared_ptr<lbcrypto::Ciphertext>& ciphertext,
      const SecretKey& secret_key) const;

  // ===== Accessors =====

  const FheParameters& parameters() const { return params_; }
  int slot_count() const { return params_.slot_count; }

  // Access to underlying OpenFHE context (for advanced operations)
  // Google C++ Style: Const reference to prevent modification
  const lbcrypto::CryptoContext& openfhe_context() const { return context_; }

 private:
  // Private constructor (use Create() factory method)
  explicit FheContext(const FheParameters& params,
                      lbcrypto::CryptoContext context);

  // Parameters
  FheParameters params_;

  // OpenFHE crypto context (RAII: automatically cleaned up)
  lbcrypto::CryptoContext context_;
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_CRYPTO_FHE_CONTEXT_H_
