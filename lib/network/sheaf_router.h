// lib/network/sheaf_router.h
//
// Unified sheaf router (Algorithm 2.1 from paper).
//
// Combines wreath product attention (local routing) with sheaf gluing
// (global consistency) into a single linear system:
//
//   [A_local  ]     [b_local ]
//   [A_gluing ] w = [b_gluing]
//
// Solve: w* = (A^H A)^{-1} A^H b (single least-squares)
//
// Residual error: ||Aw* - b||² = cohomological obstruction
// Zero residual → perfect learnability & global consistency
//
// Author: bon-cdp (shakilflynn@gmail.com)
// Date: 2025-11-11

#ifndef F2CHAT_LIB_NETWORK_SHEAF_ROUTER_H_
#define F2CHAT_LIB_NETWORK_SHEAF_ROUTER_H_

#include <vector>
#include <memory>
#include "lib/network/patch.h"
#include "lib/network/gluing.h"
#include "absl/status/statusor.h"
#include "absl/status/status.h"

namespace f2chat {

// Problem definition for sheaf routing.
struct RoutingProblem {
  std::vector<std::shared_ptr<Patch>> patches;
  std::vector<GluingConstraint> gluings;

  // Training examples (for learning routing weights)
  std::vector<RoutingExample> examples;
};

// Result of routing solve.
struct RoutingResult {
  // Learned routing weights (one per patch)
  std::vector<RoutingWeights> patch_weights;

  // Cohomological obstruction (residual error)
  // Zero → perfect learnability & consistency
  double obstruction;

  // Was the solve successful?
  bool success;
};

// Unified sheaf router.
//
// Thread Safety: Thread-safe after construction (immutable problem).
class SheafRouter {
 public:
  // Creates sheaf router for a given routing problem.
  //
  // Args:
  //   problem: Network definition (patches + gluings + examples)
  //
  // Returns:
  //   SheafRouter instance
  static absl::StatusOr<SheafRouter> Create(const RoutingProblem& problem);

  // Learns routing via single linear solve (Algorithm 2.1).
  //
  // Steps:
  //   1. For each patch, construct local design matrix A_m and target b_m
  //   2. Assemble block-diagonal A_local and concatenated b_local
  //   3. For each gluing constraint, construct constraint row C_ij
  //   4. Assemble A_gluing and b_gluing (zero vector)
  //   5. Form global system: A_sheaf = [A_local; A_gluing], b_sheaf = [b_local; 0]
  //   6. Solve: w* = (A^H A)^{-1} A^H b
  //
  // Returns:
  //   RoutingResult with learned weights and obstruction
  //   Error if solve fails (singular matrix, etc.)
  //
  // Performance: O(n³) for matrix inversion (one-time cost)
  absl::StatusOr<RoutingResult> LearnRouting();

  // Routes polynomial through network using learned weights.
  //
  // Applies local routing φₚ at each patch in sequence,
  // verifying gluing constraints are satisfied.
  //
  // Args:
  //   message_poly: Polynomial to route
  //   source_id: Source polynomial ID
  //   dest_id: Destination polynomial ID
  //
  // Returns:
  //   Routed polynomial (arrives at destination mailbox)
  //   Error if routing fails or constraints violated
  //
  // Performance: O(num_patches * n log n)
  absl::StatusOr<Polynomial> Route(
      const Polynomial& message_poly,
      const Polynomial& source_id,
      const Polynomial& dest_id) const;

  // Verifies zero cohomological obstruction.
  //
  // Checks: ||A w* - b||² ≈ 0 (within tolerance)
  //
  // Args:
  //   weights: Learned routing weights
  //   tolerance: Allowed error (default: 1e-6)
  //
  // Returns:
  //   Residual error (should be ≈ 0)
  double VerifyConsistency(
      const RoutingResult& result,
      double tolerance = 1e-6) const;

 private:
  explicit SheafRouter(const RoutingProblem& problem);

  // Assembles local design matrix A_local and target b_local.
  void AssembleLocalSystem(
      std::vector<std::vector<double>>& A,
      std::vector<double>& b) const;

  // Assembles gluing constraint matrix A_gluing.
  void AssembleGluingSystem(
      std::vector<std::vector<double>>& A) const;

  // Solves least-squares: w* = (A^H A)^{-1} A^H b
  absl::StatusOr<std::vector<double>> SolveLeastSquares(
      const std::vector<std::vector<double>>& A,
      const std::vector<double>& b) const;

  RoutingProblem problem_;
  RoutingResult last_result_;  // Cached result from LearnRouting
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_NETWORK_SHEAF_ROUTER_H_
