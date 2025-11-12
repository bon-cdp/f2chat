// lib/crypto/polynomial.cc
#include "lib/crypto/polynomial.h"

#include <algorithm>
#include <cmath>
#include <numbers>
#include "absl/strings/str_cat.h"

namespace f2chat {

namespace {
// Helper: Modular reduction ensuring result in [0, p-1].
inline int64_t Mod(int64_t value, int64_t modulus) {
  int64_t result = value % modulus;
  if (result < 0) result += modulus;
  return result;
}

// Helper: Modular multiplication (avoids overflow).
inline int64_t ModMul(int64_t a, int64_t b, int64_t modulus) {
  return Mod(a * b, modulus);
}

// Helper: Next power of 2 (for FFT).
inline int NextPowerOf2(int n) {
  int power = 1;
  while (power < n) power *= 2;
  return power;
}
}  // namespace

Polynomial::Polynomial() : coefficients_(RingParams::kDegree, 0) {}

Polynomial::Polynomial(const std::vector<int64_t>& coefficients) {
  coefficients_.reserve(RingParams::kDegree);

  // Copy coefficients and reduce mod p.
  for (int64_t coeff : coefficients) {
    coefficients_.push_back(ReduceMod(coeff));
  }

  // Pad with zeros if needed.
  while (coefficients_.size() < RingParams::kDegree) {
    coefficients_.push_back(0);
  }

  // Reduce mod (x^n + 1) if degree too high.
  if (coefficients_.size() > RingParams::kDegree) {
    ReduceModXn();
  }
}

int64_t Polynomial::ReduceMod(int64_t value) {
  return Mod(value, RingParams::kModulus);
}

void Polynomial::ReduceModXn() {
  // Reduce mod (x^n + 1): x^n ≡ -1
  // For coefficients [c₀, ..., c_{n-1}, c_n, ..., c_{2n-1}]:
  // Result: [c₀ - c_n, c₁ - c_{n+1}, ..., c_{n-1} - c_{2n-1}]

  while (coefficients_.size() > RingParams::kDegree) {
    std::vector<int64_t> reduced(RingParams::kDegree, 0);

    for (size_t i = 0; i < coefficients_.size(); ++i) {
      int pos = i % RingParams::kDegree;
      int cycle = i / RingParams::kDegree;

      if (cycle % 2 == 0) {
        // Even cycle: add
        reduced[pos] = ReduceMod(reduced[pos] + coefficients_[i]);
      } else {
        // Odd cycle: subtract (because x^n ≡ -1)
        reduced[pos] = ReduceMod(reduced[pos] - coefficients_[i]);
      }
    }

    coefficients_ = std::move(reduced);
  }
}

Polynomial Polynomial::Add(const Polynomial& other) const {
  std::vector<int64_t> result(RingParams::kDegree);

  for (int i = 0; i < RingParams::kDegree; ++i) {
    result[i] = ReduceMod(coefficients_[i] + other.coefficients_[i]);
  }

  return Polynomial(result);
}

Polynomial Polynomial::Subtract(const Polynomial& other) const {
  std::vector<int64_t> result(RingParams::kDegree);

  for (int i = 0; i < RingParams::kDegree; ++i) {
    result[i] = ReduceMod(coefficients_[i] - other.coefficients_[i]);
  }

  return Polynomial(result);
}

Polynomial Polynomial::Multiply(const Polynomial& other) const {
  // Polynomial multiplication via FFT (O(n log n)).
  // Convert coefficients to complex, perform FFT, pointwise multiply,
  // inverse FFT, and reduce mod p.

  int n = NextPowerOf2(2 * RingParams::kDegree);

  // Convert to complex vectors.
  std::vector<std::complex<double>> a_complex(n, 0.0);
  std::vector<std::complex<double>> b_complex(n, 0.0);

  for (int i = 0; i < RingParams::kDegree; ++i) {
    a_complex[i] = std::complex<double>(coefficients_[i], 0.0);
    b_complex[i] = std::complex<double>(other.coefficients_[i], 0.0);
  }

  // FFT.
  auto a_fft = FFT(a_complex);
  auto b_fft = FFT(b_complex);

  // Pointwise multiplication.
  std::vector<std::complex<double>> product_fft(n);
  for (int i = 0; i < n; ++i) {
    product_fft[i] = a_fft[i] * b_fft[i];
  }

  // Inverse FFT.
  auto product = IFFT(product_fft);

  // Convert back to integers and reduce mod (x^n + 1, p).
  std::vector<int64_t> result_coeffs;
  result_coeffs.reserve(product.size());
  for (const auto& c : product) {
    result_coeffs.push_back(static_cast<int64_t>(std::round(c.real())));
  }

  return Polynomial(result_coeffs);
}

Polynomial Polynomial::MultiplyScalar(int64_t scalar) const {
  std::vector<int64_t> result(RingParams::kDegree);

  for (int i = 0; i < RingParams::kDegree; ++i) {
    result[i] = ModMul(coefficients_[i], scalar, RingParams::kModulus);
  }

  return Polynomial(result);
}

Polynomial Polynomial::Rotate(int positions) const {
  // Rotate coefficients cyclically.
  // Positive: rotate right, negative: rotate left.

  std::vector<int64_t> result(RingParams::kDegree);
  int n = RingParams::kDegree;

  // Normalize positions to [0, n).
  int shift = ((positions % n) + n) % n;

  for (int i = 0; i < n; ++i) {
    int new_pos = (i + shift) % n;
    result[new_pos] = coefficients_[i];
  }

  return Polynomial(result);
}

Polynomial Polynomial::Negate() const {
  std::vector<int64_t> result(RingParams::kDegree);

  for (int i = 0; i < RingParams::kDegree; ++i) {
    result[i] = ReduceMod(-coefficients_[i]);
  }

  return Polynomial(result);
}

absl::StatusOr<Polynomial> Polynomial::Encode(
    const std::vector<int64_t>& values) {
  if (values.size() > RingParams::kDegree) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Too many values to encode: ", values.size(),
        " > ", RingParams::kDegree));
  }

  return Polynomial(values);
}

std::vector<int64_t> Polynomial::Decode() const {
  return coefficients_;
}

absl::StatusOr<Polynomial> Polynomial::ProjectToCharacter(
    int character_index) const {
  if (character_index < 0 || character_index >= RingParams::kNumCharacters) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Character index out of range: ", character_index,
        " (must be 0-", RingParams::kNumCharacters - 1, ")"));
  }

  // Character projection via DFT.
  // χⱼ(k) = exp(2πijk/n) where n = kNumCharacters
  // Proj_χⱼ(p) = (1/n) Σₖ χⱼ(k)* · p_k

  int n = RingParams::kNumCharacters;
  double factor = 1.0 / n;

  std::vector<int64_t> projection(RingParams::kDegree, 0);

  // For each coefficient slot.
  for (int slot = 0; slot < RingParams::kDegree; ++slot) {
    // Compute DFT component.
    std::complex<double> sum(0.0, 0.0);

    for (int k = 0; k < n; ++k) {
      // ω = exp(-2πi/n) (note: conjugate for inverse)
      double angle = -2.0 * std::numbers::pi * character_index * k / n;
      std::complex<double> omega(std::cos(angle), std::sin(angle));

      // Get coefficient (cycling through if slot >= n).
      int coeff_idx = (slot * n + k) % RingParams::kDegree;
      sum += omega * static_cast<double>(coefficients_[coeff_idx]);
    }

    projection[slot] = ReduceMod(static_cast<int64_t>(std::round(sum.real() * factor)));
  }

  return Polynomial(projection);
}

std::vector<Polynomial> Polynomial::ProjectToAllCharacters() const {
  std::vector<Polynomial> projections;
  projections.reserve(RingParams::kNumCharacters);

  for (int j = 0; j < RingParams::kNumCharacters; ++j) {
    auto proj = ProjectToCharacter(j);
    if (proj.ok()) {
      projections.push_back(std::move(proj).value());
    }
  }

  return projections;
}

bool Polynomial::operator==(const Polynomial& other) const {
  return coefficients_ == other.coefficients_;
}

bool Polynomial::operator!=(const Polynomial& other) const {
  return !(*this == other);
}

// FFT implementation (Cooley-Tukey algorithm).
std::vector<std::complex<double>> Polynomial::FFT(
    const std::vector<std::complex<double>>& input) {
  int n = input.size();
  if (n <= 1) return input;

  // Divide: even and odd indices.
  std::vector<std::complex<double>> even, odd;
  even.reserve(n / 2);
  odd.reserve(n / 2);

  for (int i = 0; i < n; i += 2) {
    even.push_back(input[i]);
    if (i + 1 < n) odd.push_back(input[i + 1]);
  }

  // Conquer: recursive FFT.
  auto even_fft = FFT(even);
  auto odd_fft = FFT(odd);

  // Combine.
  std::vector<std::complex<double>> result(n);
  for (int k = 0; k < n / 2; ++k) {
    double angle = -2.0 * std::numbers::pi * k / n;
    std::complex<double> omega(std::cos(angle), std::sin(angle));
    std::complex<double> t = omega * odd_fft[k];

    result[k] = even_fft[k] + t;
    result[k + n / 2] = even_fft[k] - t;
  }

  return result;
}

// Inverse FFT.
std::vector<std::complex<double>> Polynomial::IFFT(
    const std::vector<std::complex<double>>& input) {
  int n = input.size();

  // Conjugate input.
  std::vector<std::complex<double>> conjugated(n);
  for (int i = 0; i < n; ++i) {
    conjugated[i] = std::conj(input[i]);
  }

  // Apply FFT.
  auto result = FFT(conjugated);

  // Conjugate output and scale.
  for (int i = 0; i < n; ++i) {
    result[i] = std::conj(result[i]) / static_cast<double>(n);
  }

  return result;
}

}  // namespace f2chat
