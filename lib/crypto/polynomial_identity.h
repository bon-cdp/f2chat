// lib/crypto/polynomial_identity.h
//
// Device-held polynomial identities for metadata privacy.
//
// Only the device knows the mapping: real_identity ↔ polynomial.
// Server sees polynomials only (cannot link to real identities).
//
// Key Properties:
// - Unlinkable: polynomial ID is cryptographically random
// - Rotatable: periodic rotation prevents tracking over time
// - Local-only mapping: contact names ↔ polynomial IDs
//
// Author: bon-cdp (shakilflynn@gmail.com)
// Date: 2025-11-11

#ifndef F2CHAT_LIB_CRYPTO_POLYNOMIAL_IDENTITY_H_
#define F2CHAT_LIB_CRYPTO_POLYNOMIAL_IDENTITY_H_

#include <string>
#include <vector>
#include "lib/crypto/polynomial.h"
#include "absl/status/statusor.h"
#include "absl/status/status.h"
#include "absl/container/flat_hash_map.h"
#include "absl/time/time.h"

namespace f2chat {

// Polynomial identity for a user.
//
// Thread Safety: NOT thread-safe. Use external locking.
//
// Storage: Device-local only (SQLite, encrypted). Not yet implemented.
class PolynomialIdentity {
 public:
  // Creates identity manager for a user.
  //
  // Generates a cryptographically random polynomial ID that is
  // unlinkable to the real identity.
  //
  // Args:
  //   real_identity: Phone number, email, or username (never sent to server)
  //   password: Device encryption password (for future local storage)
  //
  // Returns:
  //   PolynomialIdentity instance with fresh polynomial ID
  //   Error if real_identity is empty
  //
  // Performance: ~10ms (generates random polynomial)
  static absl::StatusOr<PolynomialIdentity> Create(
      const std::string& real_identity,
      const std::string& password);

  // Getters.

  const std::string& real_identity() const { return real_identity_; }
  const Polynomial& polynomial_id() const { return polynomial_id_; }

  absl::Time created_at() const { return created_at_; }

  // Rotates polynomial ID (for unlinkability over time).
  //
  // Generates a new cryptographically random polynomial ID.
  // Old ID is discarded (cannot be linked to new ID).
  //
  // Note: In production, would need cryptographic proof that
  // old/new IDs belong to same real identity (zero-knowledge proof).
  //
  // Returns:
  //   Success status
  //   Error if rotation fails
  //
  // Performance: ~10ms
  absl::Status RotatePolynomialID();

  // Contact management (device-local only).

  // Looks up contact's polynomial ID.
  //
  // Args:
  //   contact_name: Human-readable name (e.g., "Bob")
  //
  // Returns:
  //   Contact's polynomial ID
  //   Error if contact not found
  absl::StatusOr<Polynomial> LookupContactPolynomial(
      const std::string& contact_name) const;

  // Adds contact to local mapping.
  //
  // Args:
  //   contact_name: Human-readable name
  //   their_polynomial: Contact's polynomial ID (exchanged via QR, etc.)
  //
  // Returns:
  //   Success status
  //   Error if contact_name empty
  absl::Status AddContact(
      const std::string& contact_name,
      const Polynomial& their_polynomial);

  // Removes contact from local mapping.
  //
  // Args:
  //   contact_name: Name to remove
  //
  // Returns:
  //   Success status
  //   Error if contact not found
  absl::Status RemoveContact(const std::string& contact_name);

  // Lists all contacts.
  //
  // Returns:
  //   Vector of contact names
  std::vector<std::string> ListContacts() const;

 private:
  PolynomialIdentity(const std::string& real_identity,
                     const std::string& password,
                     const Polynomial& initial_polynomial);

  // Generates a cryptographically random polynomial ID.
  static Polynomial GenerateRandomPolynomial();

  std::string real_identity_;        // Never sent to server
  std::string password_;             // For local storage encryption (future)
  Polynomial polynomial_id_;         // Current unlinkable ID
  absl::Time created_at_;            // When ID was created/rotated

  // Contact mapping: name → polynomial (device-local only)
  absl::flat_hash_map<std::string, Polynomial> contacts_;
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_CRYPTO_POLYNOMIAL_IDENTITY_H_
