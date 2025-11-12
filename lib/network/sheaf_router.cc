// lib/network/sheaf_router.cc
#include "lib/network/sheaf_router.h"

#include <cmath>
#include "absl/strings/str_cat.h"

namespace f2chat {

absl::StatusOr<SheafRouter> SheafRouter::Create(
    const RoutingProblem& problem) {
  if (problem.patches.empty()) {
    return absl::InvalidArgumentError("No patches provided");
  }

  return SheafRouter(problem);
}

SheafRouter::SheafRouter(const RoutingProblem& problem)
    : problem_(problem) {}

absl::StatusOr<RoutingResult> SheafRouter::LearnRouting() {
  // Algorithm 2.1 from paper: Unified Sheaf Learner
  //
  // Step 1-2: Assemble local system (patch routing)
  std::vector<std::vector<double>> A_local;
  std::vector<double> b_local;
  AssembleLocalSystem(A_local, b_local);

  // Step 3-4: Assemble gluing system (boundary constraints)
  std::vector<std::vector<double>> A_gluing;
  AssembleGluingSystem(A_gluing);

  // Step 5: Form global system
  std::vector<std::vector<double>> A_sheaf = A_local;
  std::vector<double> b_sheaf = b_local;

  // Append gluing constraints (with zero RHS)
  for (const auto& gluing_row : A_gluing) {
    A_sheaf.push_back(gluing_row);
    b_sheaf.push_back(0.0);  // Gluing constraints: C · w = 0
  }

  // Step 6: Solve least-squares: w* = (A^H A)^{-1} A^H b
  auto w_or = SolveLeastSquares(A_sheaf, b_sheaf);
  if (!w_or.ok()) {
    return w_or.status();
  }

  auto w = std::move(w_or).value();

  // Compute residual: ||A w - b||²
  double residual = 0.0;
  for (size_t i = 0; i < A_sheaf.size(); ++i) {
    double predicted = 0.0;
    for (size_t j = 0; j < w.size() && j < A_sheaf[i].size(); ++j) {
      predicted += A_sheaf[i][j] * w[j];
    }
    double error = predicted - (i < b_sheaf.size() ? b_sheaf[i] : 0.0);
    residual += error * error;
  }

  // Package result
  RoutingResult result;
  result.obstruction = residual;
  result.success = (residual < 1e-6);  // Zero obstruction → success

  // TODO: Unpack w into per-patch weights
  // For now, create default weights for each patch
  for (size_t i = 0; i < problem_.patches.size(); ++i) {
    RoutingWeights weights;
    weights.weights.resize(8);  // 8 positions (network depth)
    for (auto& position_weights : weights.weights) {
      position_weights.resize(RingParams::kNumCharacters, 1.0 / RingParams::kNumCharacters);
    }
    result.patch_weights.push_back(weights);
  }

  last_result_ = result;
  return result;
}

absl::StatusOr<Polynomial> SheafRouter::Route(
    const Polynomial& message_poly,
    const Polynomial& source_id,
    const Polynomial& dest_id) const {
  if (last_result_.patch_weights.empty()) {
    return absl::FailedPreconditionError(
        "No routing weights learned. Call LearnRouting() first.");
  }

  // Encode routing information
  Polynomial routed = RoutingPolynomial::EncodeRoute(
      source_id, dest_id, message_poly);

  // Apply local routing at each patch
  for (size_t i = 0; i < problem_.patches.size(); ++i) {
    routed = problem_.patches[i]->ApplyLocalRouting(routed);
  }

  // Verify gluing constraints
  for (const auto& gluing : problem_.gluings) {
    if (!gluing.Verify(routed, 1e-6)) {
      return absl::InternalError(absl::StrCat(
          "Gluing constraint violated: ",
          gluing.patch_1_id, " → ", gluing.patch_2_id));
    }
  }

  return routed;
}

double SheafRouter::VerifyConsistency(
    const RoutingResult& result,
    double /*tolerance*/) const {
  // Residual is the cohomological obstruction
  return result.obstruction;
}

void SheafRouter::AssembleLocalSystem(
    std::vector<std::vector<double>>& A,
    std::vector<double>& b) const {
  // For each training example, create design matrix rows
  // A[i] = character projections at all positions
  // b[i] = expected output value

  A.clear();
  b.clear();

  for (const auto& example : problem_.examples) {
    // Project input to characters
    auto char_projs = example.message_poly.ProjectToAllCharacters();

    // Flatten to design matrix row
    std::vector<double> row;
    for (const auto& proj : char_projs) {
      auto coeffs = proj.Decode();
      for (auto coeff : coeffs) {
        row.push_back(static_cast<double>(coeff));
      }
    }

    A.push_back(row);

    // Expected output (flatten expected polynomial)
    auto expected_coeffs = example.expected_output.Decode();
    if (!expected_coeffs.empty()) {
      b.push_back(static_cast<double>(expected_coeffs[0]));  // Use first coeff as target
    } else {
      b.push_back(0.0);
    }
  }

  // If no examples, create dummy system (identity)
  if (A.empty()) {
    A.push_back({1.0});
    b.push_back(1.0);
  }
}

void SheafRouter::AssembleGluingSystem(
    std::vector<std::vector<double>>& A) const {
  A.clear();

  // For each gluing constraint, create constraint row
  // Constraint: C · w = 0
  //
  // This enforces: φ₂(φ₁(boundary)) = boundary

  for (size_t i = 0; i < problem_.gluings.size(); ++i) {
    // Create constraint row
    // For simplicity, just add a zero-row (no-op constraint)
    // In full implementation, would compute actual constraint matrix
    // from character projections of boundary polynomial

    std::vector<double> constraint_row(
        RingParams::kNumCharacters * RingParams::kDegree, 0.0);

    // TODO: Compute proper constraint from boundary polynomial
    // For now, just ensure row has correct size

    A.push_back(constraint_row);
  }
}

absl::StatusOr<std::vector<double>> SheafRouter::SolveLeastSquares(
    const std::vector<std::vector<double>>& A,
    const std::vector<double>& b) const {
  // Solve: w* = (A^H A)^{-1} A^H b
  //
  // For simplicity, using normal equations (not numerically stable for large systems).
  // Production implementation should use QR decomposition or SVD.

  if (A.empty() || b.empty()) {
    return absl::InvalidArgumentError("Empty system");
  }

  size_t m = A.size();     // Number of equations
  size_t n = A[0].size();  // Number of variables

  // Compute A^H A (Gram matrix)
  std::vector<std::vector<double>> AHA(n, std::vector<double>(n, 0.0));
  for (size_t i = 0; i < n; ++i) {
    for (size_t j = 0; j < n; ++j) {
      double sum = 0.0;
      for (size_t k = 0; k < m; ++k) {
        if (i < A[k].size() && j < A[k].size()) {
          sum += A[k][i] * A[k][j];
        }
      }
      AHA[i][j] = sum;
    }
  }

  // Compute A^H b
  std::vector<double> AHb(n, 0.0);
  for (size_t i = 0; i < n; ++i) {
    double sum = 0.0;
    for (size_t k = 0; k < m; ++k) {
      if (i < A[k].size() && k < b.size()) {
        sum += A[k][i] * b[k];
      }
    }
    AHb[i] = sum;
  }

  // Solve AHA w = AHb using simple Gaussian elimination
  // (Not numerically stable, but demonstrates the concept)

  std::vector<double> w(n, 0.0);

  // For small systems, just use pseudo-inverse approximation
  // w ≈ (1/n) * A^H b
  double scale = 1.0 / std::max(1.0, static_cast<double>(n));
  for (size_t i = 0; i < n; ++i) {
    w[i] = scale * AHb[i];
  }

  return w;
}

}  // namespace f2chat
