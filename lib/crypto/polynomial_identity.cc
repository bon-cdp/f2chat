// lib/crypto/polynomial_identity.cc
#include "lib/crypto/polynomial_identity.h"

#include <random>
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"

namespace f2chat {

absl::StatusOr<PolynomialIdentity> PolynomialIdentity::Create(
    const std::string& real_identity,
    const std::string& password) {
  if (real_identity.empty()) {
    return absl::InvalidArgumentError("Real identity cannot be empty");
  }
  if (password.empty()) {
    return absl::InvalidArgumentError("Password cannot be empty");
  }

  Polynomial initial_polynomial = GenerateRandomPolynomial();
  return PolynomialIdentity(real_identity, password, initial_polynomial);
}

PolynomialIdentity::PolynomialIdentity(const std::string& real_identity,
                                       const std::string& password,
                                       const Polynomial& initial_polynomial)
    : real_identity_(real_identity),
      password_(password),
      polynomial_id_(initial_polynomial),
      created_at_(absl::Now()) {}

Polynomial PolynomialIdentity::GenerateRandomPolynomial() {
  // Generate cryptographically random coefficients.
  std::vector<int64_t> coefficients;
  coefficients.reserve(RingParams::kDegree);

  // Use std::random_device for cryptographic randomness.
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<int64_t> dist(0, RingParams::kModulus - 1);

  for (int i = 0; i < RingParams::kDegree; ++i) {
    coefficients.push_back(dist(gen));
  }

  return Polynomial(coefficients);
}

absl::Status PolynomialIdentity::RotatePolynomialID() {
  polynomial_id_ = GenerateRandomPolynomial();
  created_at_ = absl::Now();

  // TODO: Generate cryptographic proof that old/new IDs belong to same
  // real identity. This would use a zero-knowledge proof or signature-based
  // proof so contacts can verify the rotation is legitimate.

  return absl::OkStatus();
}

absl::StatusOr<Polynomial> PolynomialIdentity::LookupContactPolynomial(
    const std::string& contact_name) const {
  auto it = contacts_.find(contact_name);
  if (it == contacts_.end()) {
    return absl::NotFoundError(
        absl::StrCat("Contact not found: ", contact_name));
  }
  return it->second;
}

absl::Status PolynomialIdentity::AddContact(
    const std::string& contact_name,
    const Polynomial& their_polynomial) {
  if (contact_name.empty()) {
    return absl::InvalidArgumentError("Contact name cannot be empty");
  }

  contacts_[contact_name] = their_polynomial;
  return absl::OkStatus();
}

absl::Status PolynomialIdentity::RemoveContact(
    const std::string& contact_name) {
  if (contacts_.erase(contact_name) == 0) {
    return absl::NotFoundError(
        absl::StrCat("Contact not found: ", contact_name));
  }
  return absl::OkStatus();
}

std::vector<std::string> PolynomialIdentity::ListContacts() const {
  std::vector<std::string> names;
  names.reserve(contacts_.size());

  for (const auto& [name, _] : contacts_) {
    names.push_back(name);
  }

  return names;
}

}  // namespace f2chat
