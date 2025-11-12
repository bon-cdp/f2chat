// lib/crypto/encrypted_polynomial.cc
//
// Implementation of encrypted polynomial wrapper.

#include "lib/crypto/encrypted_polynomial.h"
#include "absl/strings/str_format.h"

namespace f2chat {

// Static factory: Encrypt plaintext polynomial
absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::Encrypt(
    const Polynomial& polynomial,
    const PublicKey& public_key,
    const FHEContext& fhe_context) {
  // Encrypt polynomial coefficients using FHE context
  auto ciphertext_or = fhe_context.Encrypt(polynomial.coefficients(), public_key);
  if (!ciphertext_or.ok()) {
    return ciphertext_or.status();
  }

  return EncryptedPolynomial(std::move(ciphertext_or).value());
}

// Decrypt to plaintext polynomial
absl::StatusOr<Polynomial> EncryptedPolynomial::Decrypt(
    const PrivateKey& private_key,
    const FHEContext& fhe_context) const {
  // Decrypt ciphertext using FHE context
  auto coefficients_or = fhe_context.Decrypt(ciphertext_, private_key);
  if (!coefficients_or.ok()) {
    return coefficients_or.status();
  }

  // Construct polynomial from decrypted coefficients
  return Polynomial(std::move(coefficients_or).value());
}

// Homomorphic operations

absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::Add(
    const EncryptedPolynomial& other,
    const FHEContext& fhe_context) const {
  // Homomorphic addition: Enc(a) + Enc(b) → Enc(a + b)
  auto result_ct_or = fhe_context.HomomorphicAdd(ciphertext_, other.ciphertext_);
  if (!result_ct_or.ok()) {
    return result_ct_or.status();
  }

  return EncryptedPolynomial(std::move(result_ct_or).value());
}

absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::Subtract(
    const EncryptedPolynomial& other,
    const FHEContext& fhe_context) const {
  // Homomorphic subtraction: Enc(a) - Enc(b) → Enc(a - b)
  auto result_ct_or = fhe_context.HomomorphicSubtract(ciphertext_, other.ciphertext_);
  if (!result_ct_or.ok()) {
    return result_ct_or.status();
  }

  return EncryptedPolynomial(std::move(result_ct_or).value());
}

absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::MultiplyScalar(
    int64_t scalar,
    const FHEContext& fhe_context) const {
  // Homomorphic scalar multiplication: k * Enc(a) → Enc(k * a)
  auto result_ct_or = fhe_context.HomomorphicMultiplyScalar(ciphertext_, scalar);
  if (!result_ct_or.ok()) {
    return result_ct_or.status();
  }

  return EncryptedPolynomial(std::move(result_ct_or).value());
}

absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::Rotate(
    int positions,
    const FHEContext& fhe_context) const {
  // Homomorphic rotation: Enc(a) → Enc(rotated(a))
  auto result_ct_or = fhe_context.HomomorphicRotate(ciphertext_, positions);
  if (!result_ct_or.ok()) {
    return result_ct_or.status();
  }

  return EncryptedPolynomial(std::move(result_ct_or).value());
}

absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::Negate(
    const FHEContext& fhe_context) const {
  // Homomorphic negation: Enc(a) → Enc(-a)
  // Implemented as scalar multiplication by -1
  return MultiplyScalar(-1, fhe_context);
}

// Character projection (homomorphic DFT)
absl::StatusOr<EncryptedPolynomial> EncryptedPolynomial::ProjectToCharacter(
    int character_index,
    const FHEContext& fhe_context) const {
  (void)fhe_context;  // Suppress unused parameter warning

  if (character_index < 0 || character_index >= RingParams::kNumCharacters) {
    return absl::InvalidArgumentError(absl::StrFormat(
        "Invalid character index: %d (must be 0 to %d)",
        character_index, RingParams::kNumCharacters - 1));
  }

  // TODO: Implement homomorphic character projection
  //
  // Planned implementation:
  // 1. Compute DFT basis weights for character χⱼ
  // 2. For each position k, apply homomorphic rotation + scalar multiplication:
  //    proj = Σₖ χⱼ(k) * Rotate(Enc(poly), k)
  // 3. Scale by 1/n (using homomorphic scalar multiplication)
  //
  // This allows server to compute character projections on encrypted data!
  //
  // Formula:
  //   Proj_χⱼ(Enc(p)) = (1/n) Σₖ χⱼ(k) * Enc(p(ωᵏ))
  // where ω is a primitive nth root of unity.
  //
  // Example (for character 0, identity):
  //   Enc(Proj_χ₀(p)) = (1/n) * Enc(sum of all coefficients)
  //
  // This is depth-0 because:
  // - Rotation: depth-0 (automorphism)
  // - Scalar multiplication: depth-0 (plaintext-ciphertext)
  // - Addition: depth-0

  return absl::UnimplementedError(
      "EncryptedPolynomial::ProjectToCharacter() - Homomorphic DFT pending");
}

absl::StatusOr<std::vector<EncryptedPolynomial>>
EncryptedPolynomial::ProjectToAllCharacters(
    const FHEContext& fhe_context) const {
  std::vector<EncryptedPolynomial> projections;
  projections.reserve(RingParams::kNumCharacters);

  // Project onto each character χⱼ
  for (int j = 0; j < RingParams::kNumCharacters; ++j) {
    auto proj_or = ProjectToCharacter(j, fhe_context);
    if (!proj_or.ok()) {
      return proj_or.status();
    }
    projections.push_back(std::move(proj_or).value());
  }

  return projections;
}

// Debug string (does NOT decrypt!)
std::string EncryptedPolynomial::DebugString() const {
  return absl::StrFormat(
      "EncryptedPolynomial{ciphertext_ptr=%p}",
      ciphertext_.get());
}

// Private constructor
EncryptedPolynomial::EncryptedPolynomial(Ciphertext ciphertext)
    : ciphertext_(ciphertext) {}

}  // namespace f2chat
