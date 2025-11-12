// lib/crypto/routing_polynomial.cc
#include "lib/crypto/routing_polynomial.h"

#include <cmath>
#include "absl/strings/str_cat.h"

namespace f2chat {

Polynomial RoutingPolynomial::EncodeRoute(
    const Polynomial& source_poly,
    const Polynomial& destination_poly,
    const Polynomial& message_poly) {
  // Simple XOR-style encoding (reversible)
  // routed = message XOR destination
  // This allows: message = routed XOR destination
  //
  // For polynomials: XOR = Add (in Z_p, addition is like XOR)

  (void)source_poly;  // Not used in simple encoding

  // Just add message and destination (reversible via subtraction)
  return message_poly.Add(destination_poly);
}

absl::StatusOr<Polynomial> RoutingPolynomial::ExtractMessage(
    const Polynomial& routed_poly,
    const Polynomial& my_poly_id) {
  // Extraction: Reverse the encoding
  // Since encoded = message + destination
  // Then: message = encoded - destination

  return routed_poly.Subtract(my_poly_id);
}

absl::StatusOr<RoutingWeights> RoutingPolynomial::LearnRoutingWeights(
    const std::vector<RoutingExample>& examples,
    int num_positions,
    int num_characters) {
  if (examples.empty()) {
    return absl::InvalidArgumentError("No training examples provided");
  }
  if (num_positions <= 0 || num_characters <= 0) {
    return absl::InvalidArgumentError("Invalid dimensions");
  }

  // Initialize weights to simple defaults for now.
  // TODO: Implement full closed-form solve from paper.
  //   w* = (A^H A)^{-1} A^H b
  // where A = character projection matrix, b = expected outputs.

  RoutingWeights weights;
  weights.weights.resize(num_positions);

  for (int p = 0; p < num_positions; ++p) {
    weights.weights[p].resize(num_characters);

    // Simple initialization: uniform weights
    // In full implementation, would solve linear system
    for (int j = 0; j < num_characters; ++j) {
      weights.weights[p][j] = 1.0 / num_characters;
    }
  }

  // TODO: Implement actual learning:
  // 1. For each example, compute character projections
  // 2. Assemble design matrix A
  // 3. Solve w = (A^H A)^{-1} A^H b (QR decomposition or SVD)
  // 4. Verify residual = 0 (zero cohomological obstruction)

  return weights;
}

Polynomial RoutingPolynomial::ApplyRoutingWeights(
    const Polynomial& input,
    const RoutingWeights& weights) {
  // Wreath product attention: position-dependent character weighting
  //
  // For position p:
  //   output[p] = Σⱼ w[p][j] * Proj_χⱼ(input)[p]

  int num_positions = weights.num_positions();
  int num_characters = weights.num_characters();

  // Project input to all characters
  auto character_projections = input.ProjectToAllCharacters();

  if (character_projections.size() != static_cast<size_t>(num_characters)) {
    // Fallback: return input unchanged if dimensions mismatch
    return input;
  }

  // Initialize result with zeros
  std::vector<int64_t> result_coeffs(RingParams::kDegree, 0);

  // For each position (coefficient in result polynomial)
  for (int p = 0; p < num_positions && p < RingParams::kDegree; ++p) {
    double weighted_sum = 0.0;

    // Sum over characters: Σⱼ w[p][j] * Proj_χⱼ(input)[p]
    for (int j = 0; j < num_characters; ++j) {
      auto proj_coeffs = character_projections[j].Decode();
      if (p < static_cast<int>(proj_coeffs.size())) {
        weighted_sum += weights.weights[p][j] * proj_coeffs[p];
      }
    }

    result_coeffs[p] = static_cast<int64_t>(std::round(weighted_sum));
  }

  return Polynomial(result_coeffs);
}

int64_t RoutingPolynomial::ExtractMailboxID(const Polynomial& poly) {
  // Mailbox ID = hash of first k coefficients
  auto coeffs = poly.Decode();

  const int kMailboxIDSize = 64;
  int64_t hash = 0;

  for (int i = 0; i < kMailboxIDSize && i < static_cast<int>(coeffs.size()); ++i) {
    hash ^= (coeffs[i] << (i % 32));  // XOR mixing
  }

  return hash;
}

Polynomial RoutingPolynomial::EmbedMailboxID(
    int64_t mailbox_id,
    const Polynomial& message) {
  auto message_coeffs = message.Decode();

  // Embed mailbox ID in first k coefficients
  const int kMailboxIDSize = 64;

  std::vector<int64_t> embedded_coeffs(RingParams::kDegree, 0);

  // Encode mailbox ID (simple: spread bits across coefficients)
  for (int i = 0; i < kMailboxIDSize; ++i) {
    embedded_coeffs[i] = (mailbox_id >> i) & 1;  // Extract bit i
  }

  // Append message in higher-order coefficients
  for (size_t i = 0; i < message_coeffs.size() &&
       (i + kMailboxIDSize) < embedded_coeffs.size(); ++i) {
    embedded_coeffs[i + kMailboxIDSize] = message_coeffs[i];
  }

  return Polynomial(embedded_coeffs);
}

}  // namespace f2chat
