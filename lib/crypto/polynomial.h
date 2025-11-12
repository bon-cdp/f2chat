// lib/crypto/polynomial.h
//
// Polynomial ring operations for metadata-private routing.
//
// This implements polynomials in Z_p[x]/(x^n + 1) where:
// - p = 65537 (prime modulus)
// - n = 4096 (polynomial degree)
//
// All operations are depth-0 (linear algebra only), making them
// FHE-compatible and efficient for algebraic routing.
//
// Author: bon-cdp (shakilflynn@gmail.com)
// Date: 2025-11-11

#ifndef F2CHAT_LIB_CRYPTO_POLYNOMIAL_H_
#define F2CHAT_LIB_CRYPTO_POLYNOMIAL_H_

#include <vector>
#include <complex>
#include <cstdint>
#include "absl/status/statusor.h"
#include "absl/status/status.h"
#include "lib/crypto/polynomial_params.h"

namespace f2chat {

// RingParams is defined in polynomial_params.h
// Default: SafeParams (kDegree=64, kNumCharacters=8)
// Change to MediumParams or ProductionParams as needed

// Polynomial in Z_p[x]/(x^n + 1).
//
// Representation: p(x) = c₀ + c₁x + c₂x² + ... + c_{n-1}x^{n-1}
// where cᵢ ∈ Z_p (integers mod p).
//
// Thread Safety: Immutable after construction (thread-safe).
//
// Performance:
// - Add: O(n) = O(4096)
// - Multiply: O(n log n) via FFT
// - Rotate: O(n)
class Polynomial {
 public:
  // Constructs zero polynomial.
  Polynomial();

  // Constructs from coefficient vector.
  //
  // Args:
  //   coefficients: Coefficient vector (c₀, c₁, ..., c_{n-1})
  //
  // If coefficients.size() < n, pads with zeros.
  // If coefficients.size() > n, reduces mod (x^n + 1).
  explicit Polynomial(const std::vector<int64_t>& coefficients);

  // Ring operations (all depth-0).

  // Addition: (a + b) mod p.
  //
  // Returns:
  //   Polynomial with coefficients (aᵢ + bᵢ) mod p
  //
  // Performance: O(n) = O(4096)
  Polynomial Add(const Polynomial& other) const;

  // Subtraction: (a - b) mod p.
  //
  // Returns:
  //   Polynomial with coefficients (aᵢ - bᵢ) mod p
  //
  // Performance: O(n)
  Polynomial Subtract(const Polynomial& other) const;

  // Multiplication: (a * b) mod (x^n + 1, p).
  //
  // Uses FFT for efficiency: O(n log n) instead of O(n²).
  //
  // Returns:
  //   Polynomial product mod (x^n + 1, p)
  //
  // Performance: O(n log n) ≈ O(49152)
  Polynomial Multiply(const Polynomial& other) const;

  // Scalar multiplication: (k * a) mod p.
  //
  // Args:
  //   scalar: Integer scalar
  //
  // Returns:
  //   Polynomial with coefficients (k * aᵢ) mod p
  //
  // Performance: O(n)
  Polynomial MultiplyScalar(int64_t scalar) const;

  // Rotation: shift coefficients cyclically.
  //
  // Rotates coefficients by `positions` to the right.
  // Equivalent to multiplying by x^positions mod (x^n + 1).
  //
  // Args:
  //   positions: Number of positions to rotate (can be negative)
  //
  // Returns:
  //   Rotated polynomial
  //
  // Performance: O(n)
  //
  // Example:
  //   p(x) = 1 + 2x + 3x²
  //   Rotate(1) = 3x^{n-1} + 1 + 2x (coefficients shifted right)
  Polynomial Rotate(int positions) const;

  // Negation: (-a) mod p.
  //
  // Returns:
  //   Polynomial with coefficients (-aᵢ) mod p
  //
  // Performance: O(n)
  Polynomial Negate() const;

  // Encoding/decoding utilities.

  // Encodes vector of integers as polynomial.
  //
  // Args:
  //   values: Integer values to encode (max kDegree values)
  //
  // Returns:
  //   Polynomial with values as coefficients
  //   Error if values.size() > kDegree
  //
  // Performance: O(n)
  static absl::StatusOr<Polynomial> Encode(
      const std::vector<int64_t>& values);

  // Decodes polynomial to vector of integers.
  //
  // Returns:
  //   Coefficient vector (c₀, c₁, ..., c_{n-1})
  //
  // Performance: O(n)
  std::vector<int64_t> Decode() const;

  // Character projection (for wreath product attention).
  //
  // Projects polynomial onto character χⱼ using DFT.
  // For cyclic group C_n, characters form orthogonal basis.
  //
  // Projection formula:
  //   Proj_χⱼ(p) = (1/n) Σₖ χⱼ(k) · p(ωᵏ)
  // where ω is a primitive nth root of unity.
  //
  // Args:
  //   character_index: Index j (0 ≤ j < kNumCharacters)
  //
  // Returns:
  //   Projection onto character χⱼ
  //   Error if character_index out of range
  //
  // Performance: O(n log n) via FFT
  absl::StatusOr<Polynomial> ProjectToCharacter(
      int character_index) const;

  // Computes all character projections.
  //
  // Returns:
  //   Vector of projections [Proj_χ₀(p), Proj_χ₁(p), ..., Proj_χₖ(p)]
  //
  // Performance: O(k * n log n) where k = kNumCharacters
  std::vector<Polynomial> ProjectToAllCharacters() const;

  // Accessors.

  const std::vector<int64_t>& coefficients() const {
    return coefficients_;
  }

  int degree() const {
    return static_cast<int>(coefficients_.size()) - 1;
  }

  // Equality comparison.
  bool operator==(const Polynomial& other) const;
  bool operator!=(const Polynomial& other) const;

 private:
  // Coefficients: [c₀, c₁, ..., c_{n-1}]
  // All coefficients are in range [0, p-1].
  std::vector<int64_t> coefficients_;

  // Reduces coefficient mod p (ensures 0 ≤ c < p).
  static int64_t ReduceMod(int64_t value);

  // Reduces polynomial mod (x^n + 1).
  // If degree ≥ n, applies reduction: x^n ≡ -1.
  void ReduceModXn();

  // FFT helpers for efficient multiplication.
  static std::vector<std::complex<double>> FFT(
      const std::vector<std::complex<double>>& input);
  static std::vector<std::complex<double>> IFFT(
      const std::vector<std::complex<double>>& input);
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_CRYPTO_POLYNOMIAL_H_
