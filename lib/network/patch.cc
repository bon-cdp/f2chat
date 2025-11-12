// lib/network/patch.cc
#include "lib/network/patch.h"

namespace f2chat {

Patch Patch::Create(
    const std::string& patch_id,
    const RoutingWeights& weights) {
  return Patch(patch_id, weights);
}

Patch::Patch(const std::string& patch_id, const RoutingWeights& weights)
    : patch_id_(patch_id), weights_(weights) {}

Polynomial Patch::ApplyLocalRouting(const Polynomial& input) const {
  // Apply wreath product attention using routing weights.
  return RoutingPolynomial::ApplyRoutingWeights(input, weights_);
}

std::vector<Polynomial> Patch::ProjectToCharacters(
    const Polynomial& poly) const {
  // Project to all characters (DFT basis).
  return poly.ProjectToAllCharacters();
}

}  // namespace f2chat
