// lib/network/gluing.h
//
// Gluing constraints for sheaf consistency.
//
// Enforces that local routing functions φₚ agree at patch boundaries.
// This is the sheaf gluing axiom: compatible local sections combine globally.
//
// Mathematical Formulation:
//   For patches P₁, P₂ sharing boundary:
//     φ₂(φ₁(poly)) = poly at boundary
//
// As Linear Constraint:
//   C · w = 0
//   where w = vectorized routing weights, C = constraint matrix
//
// Author: bon-cdp (shakilflynn@gmail.com)
// Date: 2025-11-11

#ifndef F2CHAT_LIB_NETWORK_GLUING_H_
#define F2CHAT_LIB_NETWORK_GLUING_H_

#include <string>
#include <vector>
#include "lib/crypto/polynomial.h"
#include "absl/status/statusor.h"

namespace f2chat {

// Gluing constraint between two patches.
//
// Thread Safety: Immutable after construction (thread-safe).
struct GluingConstraint {
  std::string patch_1_id;  // First patch
  std::string patch_2_id;  // Second patch

  // Boundary polynomial: where patches meet
  Polynomial boundary_poly;

  // Constraint type
  enum class Type {
    // Continuity: φ₂(φ₁(p)) = p at boundary
    kContinuity,

    // Periodicity: φₙ(...φ₂(φ₁(p))) = p (circular routing)
    kPeriodicity,

    // Custom: User-defined constraint
    kCustom
  };
  Type type;

  // For linear system: C · w = 0
  // Each row of C encodes one constraint equation.
  // (Populated by SheafRouter during system assembly)
  std::vector<std::vector<double>> constraint_matrix;  // C
  std::vector<double> constraint_rhs;                  // 0 vector

  // Verifies that routing satisfies this gluing constraint.
  //
  // Checks: φ₂(φ₁(boundary_poly)) ≈ boundary_poly (within tolerance)
  //
  // Args:
  //   routed_poly: Result of applying φ₂ ∘ φ₁
  //   tolerance: Allowed error (for numerical stability)
  //
  // Returns:
  //   true if constraint satisfied, false otherwise
  bool Verify(const Polynomial& routed_poly, double tolerance = 1e-6) const;
};

// Builder for gluing constraints.
class GluingConstraintBuilder {
 public:
  // Creates continuity constraint: φ₂(φ₁(p)) = p at boundary.
  //
  // Args:
  //   patch_1_id: First patch ID
  //   patch_2_id: Second patch ID
  //   boundary_poly: Polynomial at patch boundary
  //
  // Returns:
  //   Continuity gluing constraint
  static GluingConstraint CreateContinuity(
      const std::string& patch_1_id,
      const std::string& patch_2_id,
      const Polynomial& boundary_poly);

  // Creates periodicity constraint: circular routing returns to start.
  //
  // Used for networks with wraparound topology (e.g., ring networks).
  //
  // Args:
  //   patch_ids: Patches in order [P₁, P₂, ..., Pₙ]
  //   start_poly: Starting polynomial
  //
  // Returns:
  //   Periodicity gluing constraint
  static GluingConstraint CreatePeriodicity(
      const std::vector<std::string>& patch_ids,
      const Polynomial& start_poly);
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_NETWORK_GLUING_H_
