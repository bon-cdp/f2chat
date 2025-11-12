// lib/network/patch.h
//
// Network patch with local routing (sheaf theory).
//
// A patch represents a region of the network (geographic, subnet, etc.)
// with its own local routing function φₚ: Polynomial → Polynomial.
//
// Sheaf Property:
//   Local routing functions must satisfy gluing constraints at boundaries.
//
// Author: bon-cdp (shakilflynn@gmail.com)
// Date: 2025-11-11

#ifndef F2CHAT_LIB_NETWORK_PATCH_H_
#define F2CHAT_LIB_NETWORK_PATCH_H_

#include <string>
#include "lib/crypto/polynomial.h"
#include "lib/crypto/routing_polynomial.h"
#include "absl/status/statusor.h"

namespace f2chat {

// Network patch definition.
//
// Thread Safety: Thread-safe after construction (immutable weights).
class Patch {
 public:
  // Creates a patch with given routing weights.
  //
  // Args:
  //   patch_id: Unique identifier (e.g., "us-east", "eu-west")
  //   weights: Position-dependent routing weights (wreath product)
  //
  // Returns:
  //   Patch instance
  static Patch Create(
      const std::string& patch_id,
      const RoutingWeights& weights);

  // Applies local routing function φₚ(polynomial).
  //
  // This is a ring homomorphism: φₚ(a + b) = φₚ(a) + φₚ(b)
  // Uses wreath product attention (position-dependent character weights).
  //
  // Args:
  //   input: Input polynomial to route
  //
  // Returns:
  //   Routed polynomial (still encrypted, server doesn't see plaintext)
  //
  // Performance: O(p * k * n log n) where:
  //   p = num_positions, k = num_characters, n = degree
  Polynomial ApplyLocalRouting(const Polynomial& input) const;

  // Projects polynomial to character basis (DFT).
  //
  // For wreath product decomposition:
  //   poly = Σⱼ weight_j * Proj_χⱼ(poly)
  //
  // Returns:
  //   Vector of character projections [Proj_χ₀, Proj_χ₁, ..., Proj_χₖ]
  //
  // Performance: O(k * n log n)
  std::vector<Polynomial> ProjectToCharacters(
      const Polynomial& poly) const;

  // Accessors.
  const std::string& patch_id() const { return patch_id_; }
  const RoutingWeights& weights() const { return weights_; }

 private:
  Patch(const std::string& patch_id, const RoutingWeights& weights);

  std::string patch_id_;        // Unique identifier
  RoutingWeights weights_;      // Position-dependent routing weights
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_NETWORK_PATCH_H_
