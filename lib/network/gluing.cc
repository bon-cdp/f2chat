// lib/network/gluing.cc
#include "lib/network/gluing.h"

#include <cmath>

namespace f2chat {

bool GluingConstraint::Verify(
    const Polynomial& routed_poly,
    double tolerance) const {
  // Check: routed_poly ≈ boundary_poly
  auto routed_coeffs = routed_poly.Decode();
  auto boundary_coeffs = boundary_poly.Decode();

  if (routed_coeffs.size() != boundary_coeffs.size()) {
    return false;
  }

  // Compute L2 error
  double error = 0.0;
  for (size_t i = 0; i < routed_coeffs.size(); ++i) {
    double diff = static_cast<double>(routed_coeffs[i] - boundary_coeffs[i]);
    error += diff * diff;
  }
  error = std::sqrt(error);

  return error < tolerance;
}

GluingConstraint GluingConstraintBuilder::CreateContinuity(
    const std::string& patch_1_id,
    const std::string& patch_2_id,
    const Polynomial& boundary_poly) {
  GluingConstraint constraint;
  constraint.patch_1_id = patch_1_id;
  constraint.patch_2_id = patch_2_id;
  constraint.boundary_poly = boundary_poly;
  constraint.type = GluingConstraint::Type::kContinuity;

  // Constraint matrix will be populated by SheafRouter
  // when assembling the global system.

  return constraint;
}

GluingConstraint GluingConstraintBuilder::CreatePeriodicity(
    const std::vector<std::string>& patch_ids,
    const Polynomial& start_poly) {
  GluingConstraint constraint;

  if (!patch_ids.empty()) {
    constraint.patch_1_id = patch_ids.front();
    constraint.patch_2_id = patch_ids.back();
  }

  constraint.boundary_poly = start_poly;
  constraint.type = GluingConstraint::Type::kPeriodicity;

  return constraint;
}

}  // namespace f2chat
