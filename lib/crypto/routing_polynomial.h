// lib/crypto/routing_polynomial.h
//
// Algebraic routing via polynomial encoding.
//
// Encodes source → destination routing in polynomial coefficients.
// Server performs ring operations without seeing endpoints.
//
// Key Idea:
//   R(x) = f(P_source, P_dest, message)
//   Server applies φ(R(x)) using ring homomorphisms
//   Polynomial "routes itself" to correct mailbox
//
// Author: bon-cdp (shakilflynn@gmail.com)
// Date: 2025-11-11

#ifndef F2CHAT_LIB_CRYPTO_ROUTING_POLYNOMIAL_H_
#define F2CHAT_LIB_CRYPTO_ROUTING_POLYNOMIAL_H_

#include <vector>
#include "lib/crypto/polynomial.h"
#include "absl/status/statusor.h"
#include "absl/status/status.h"

namespace f2chat {

// Wreath product routing weights.
//
// For each network position p and character j:
//   w[p][j] = weight for character χⱼ at position p
//
// This encodes position-dependent routing decisions.
struct RoutingWeights {
  // weights[position][character]
  std::vector<std::vector<double>> weights;

  // Number of positions (network hops)
  int num_positions() const { return static_cast<int>(weights.size()); }

  // Number of characters (DFT basis size)
  int num_characters() const {
    return weights.empty() ? 0 : static_cast<int>(weights[0].size());
  }
};

// Training example for learning routing weights.
struct RoutingExample {
  Polynomial source_poly;       // Source polynomial ID
  Polynomial destination_poly;  // Destination polynomial ID
  Polynomial message_poly;      // Message to route
  Polynomial expected_output;   // Expected routed polynomial
};

// Routing polynomial encoder/decoder.
//
// Thread Safety: All methods are thread-safe (stateless operations).
class RoutingPolynomial {
 public:
  // Encodes routing information: source → destination.
  //
  // Strategy:
  //   - Mix source and destination polynomials algebraically
  //   - Encode destination in specific coefficient positions
  //   - Result polynomial "knows" where to route
  //
  // Args:
  //   source_poly: Sender's polynomial ID
  //   destination_poly: Receiver's polynomial ID
  //   message_poly: Message content polynomial
  //
  // Returns:
  //   Routing polynomial R(x) that encodes destination
  //
  // Performance: O(n log n) (polynomial multiplication)
  static Polynomial EncodeRoute(
      const Polynomial& source_poly,
      const Polynomial& destination_poly,
      const Polynomial& message_poly);

  // Extracts message from routed polynomial.
  //
  // Inverse of EncodeRoute. Recipient uses their polynomial ID
  // to extract the original message.
  //
  // Args:
  //   routed_poly: Polynomial that arrived at destination
  //   my_poly_id: Recipient's polynomial ID
  //
  // Returns:
  //   Original message polynomial
  //   Error if extraction fails
  //
  // Performance: O(n log n)
  static absl::StatusOr<Polynomial> ExtractMessage(
      const Polynomial& routed_poly,
      const Polynomial& my_poly_id);

  // Learns routing weights from training examples.
  //
  // Uses closed-form solve (your paper, Theorem 2.1):
  //   w* = (A^H A)^{-1} A^H b
  // where A = character projections, b = expected outputs.
  //
  // Args:
  //   examples: Training data (source, dest, message, expected)
  //   num_positions: Network depth (number of hops)
  //   num_characters: DFT basis size
  //
  // Returns:
  //   Learned routing weights
  //   Error if solve fails (singular matrix)
  //
  // Performance: O(p * k * |examples|) where p=positions, k=characters
  static absl::StatusOr<RoutingWeights> LearnRoutingWeights(
      const std::vector<RoutingExample>& examples,
      int num_positions,
      int num_characters);

  // Applies routing weights to polynomial (wreath product attention).
  //
  // For each position p:
  //   output[p] = Σⱼ w[p][j] * Proj_χⱼ(input)
  //
  // Args:
  //   input: Input polynomial
  //   weights: Learned routing weights
  //
  // Returns:
  //   Output polynomial after applying position-dependent weights
  //
  // Performance: O(p * k * n log n) where p=positions, k=characters, n=degree
  static Polynomial ApplyRoutingWeights(
      const Polynomial& input,
      const RoutingWeights& weights);

 private:
  // Helper: Extract destination mailbox ID from polynomial.
  // Uses first k coefficients as mailbox identifier.
  static int64_t ExtractMailboxID(const Polynomial& poly);

  // Helper: Embed mailbox ID into polynomial coefficients.
  static Polynomial EmbedMailboxID(int64_t mailbox_id, const Polynomial& message);
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_CRYPTO_ROUTING_POLYNOMIAL_H_
