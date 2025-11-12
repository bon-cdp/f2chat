// lib/crypto/encrypted_polynomial.h
//
// Encrypted polynomial wrapper for FHE-based routing.
//
// Provides a high-level interface for working with FHE-encrypted polynomials,
// mirroring the API of the plaintext Polynomial class but operating on
// encrypted data using homomorphic operations.
//
// Key Properties:
// - Server never decrypts: All operations on encrypted data only
// - Depth-0 operations: No bootstrapping needed (add, subtract, rotate)
// - Ring homomorphisms: Operations preserve polynomial structure
//
// Thread Safety: Immutable after construction (thread-safe).
//
// Author: bon-cdp (shakilflynn@gmail.com)
// Date: 2025-11-11

#ifndef F2CHAT_LIB_CRYPTO_ENCRYPTED_POLYNOMIAL_H_
#define F2CHAT_LIB_CRYPTO_ENCRYPTED_POLYNOMIAL_H_

#include <memory>
#include <vector>
#include "lib/crypto/fhe_context.h"
#include "lib/crypto/polynomial.h"
#include "absl/status/statusor.h"
#include "absl/status/status.h"

namespace f2chat {

// Encrypted polynomial (FHE ciphertext representing polynomial coefficients).
//
// This class wraps an OpenFHE Ciphertext and provides polynomial-like
// operations that execute homomorphically on encrypted data.
//
// Example usage:
//   // Encrypt polynomial
//   Polynomial plaintext({1, 2, 3});
//   auto enc_poly = EncryptedPolynomial::Encrypt(plaintext, public_key, fhe_ctx);
//
//   // Homomorphic addition (server-side, blind!)
//   auto enc_sum = enc_poly1.Add(enc_poly2);
//
//   // Decrypt result (client-side only!)
//   auto decrypted = enc_sum.Decrypt(private_key, fhe_ctx);
//
// Thread Safety: Immutable after construction (thread-safe).
//
// Performance:
// - Encrypt: O(n log n)
// - Decrypt: O(n log n)
// - Add/Subtract: O(n) (depth-0!)
// - Rotate: O(n log n) (depth-0!)
class EncryptedPolynomial {
 public:
  // Encrypts a plaintext polynomial.
  //
  // Args:
  //   polynomial: Plaintext polynomial to encrypt
  //   public_key: Recipient's public key
  //   fhe_context: FHE crypto context
  //
  // Returns:
  //   EncryptedPolynomial containing the ciphertext
  //   Error if encryption fails
  //
  // Performance: O(n log n)
  static absl::StatusOr<EncryptedPolynomial> Encrypt(
      const Polynomial& polynomial,
      const PublicKey& public_key,
      const FHEContext& fhe_context);

  // Decrypts to plaintext polynomial.
  //
  // Args:
  //   private_key: Decryption key (device-held only!)
  //   fhe_context: FHE crypto context
  //
  // Returns:
  //   Decrypted plaintext polynomial
  //   Error if decryption fails
  //
  // Performance: O(n log n)
  //
  // Security: This should ONLY be called on the client device, never on the server!
  absl::StatusOr<Polynomial> Decrypt(
      const PrivateKey& private_key,
      const FHEContext& fhe_context) const;

  // Homomorphic ring operations (all depth-0).

  // Homomorphic addition: Enc(a) + Enc(b) → Enc(a + b).
  //
  // Args:
  //   other: Encrypted polynomial to add
  //   fhe_context: FHE crypto context
  //
  // Returns:
  //   Encrypted sum
  //   Error if operation fails
  //
  // Performance: O(n), depth-0
  //
  // Server-safe: YES (server can compute this without decrypting!)
  absl::StatusOr<EncryptedPolynomial> Add(
      const EncryptedPolynomial& other,
      const FHEContext& fhe_context) const;

  // Homomorphic subtraction: Enc(a) - Enc(b) → Enc(a - b).
  //
  // Args:
  //   other: Encrypted polynomial to subtract
  //   fhe_context: FHE crypto context
  //
  // Returns:
  //   Encrypted difference
  //   Error if operation fails
  //
  // Performance: O(n), depth-0
  //
  // Server-safe: YES
  absl::StatusOr<EncryptedPolynomial> Subtract(
      const EncryptedPolynomial& other,
      const FHEContext& fhe_context) const;

  // Homomorphic scalar multiplication: k * Enc(a) → Enc(k * a).
  //
  // Multiplies encrypted polynomial by a plaintext scalar.
  // Used for position-dependent weights in wreath product attention.
  //
  // Args:
  //   scalar: Plaintext scalar (not encrypted!)
  //   fhe_context: FHE crypto context
  //
  // Returns:
  //   Encrypted scaled polynomial
  //   Error if operation fails
  //
  // Performance: O(n), depth-0
  //
  // Server-safe: YES (server can apply known weights to encrypted data!)
  absl::StatusOr<EncryptedPolynomial> MultiplyScalar(
      int64_t scalar,
      const FHEContext& fhe_context) const;

  // Homomorphic rotation: Enc(a) → Enc(rotated(a)).
  //
  // Rotates encrypted polynomial coefficients cyclically.
  // Used for character projections in wreath product attention.
  //
  // Args:
  //   positions: Number of positions to rotate
  //   fhe_context: FHE crypto context
  //
  // Returns:
  //   Encrypted rotated polynomial
  //   Error if operation fails or rotation keys not generated
  //
  // Performance: O(n log n), depth-0
  //
  // Server-safe: YES
  absl::StatusOr<EncryptedPolynomial> Rotate(
      int positions,
      const FHEContext& fhe_context) const;

  // Homomorphic negation: Enc(a) → Enc(-a).
  //
  // Returns:
  //   Encrypted negated polynomial
  //   Error if operation fails
  //
  // Performance: O(n), depth-0
  //
  // Server-safe: YES
  absl::StatusOr<EncryptedPolynomial> Negate(
      const FHEContext& fhe_context) const;

  // Character projection (for wreath product attention on encrypted data).
  //
  // Projects encrypted polynomial onto character χⱼ using homomorphic DFT.
  // This allows the server to compute character-based routing WITHOUT
  // decrypting the polynomial!
  //
  // Args:
  //   character_index: Index j (0 ≤ j < kNumCharacters)
  //   fhe_context: FHE crypto context
  //
  // Returns:
  //   Encrypted projection onto character χⱼ
  //   Error if character_index out of range or operation fails
  //
  // Performance: O(k * n log n) where k = kNumCharacters
  //
  // Server-safe: YES (this is the key to blind routing!)
  absl::StatusOr<EncryptedPolynomial> ProjectToCharacter(
      int character_index,
      const FHEContext& fhe_context) const;

  // Computes all character projections homomorphically.
  //
  // Returns:
  //   Vector of encrypted projections [Enc(Proj_χ₀), ..., Enc(Proj_χₖ)]
  //   Error if operation fails
  //
  // Performance: O(k * n log n)
  //
  // Server-safe: YES
  absl::StatusOr<std::vector<EncryptedPolynomial>> ProjectToAllCharacters(
      const FHEContext& fhe_context) const;

  // Accessors.

  const Ciphertext& ciphertext() const { return ciphertext_; }

  // For debugging/logging only (does NOT decrypt!)
  std::string DebugString() const;

 private:
  explicit EncryptedPolynomial(Ciphertext ciphertext);

  // OpenFHE ciphertext (encrypted polynomial coefficients)
  Ciphertext ciphertext_;
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_CRYPTO_ENCRYPTED_POLYNOMIAL_H_
