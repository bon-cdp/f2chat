// test/crypto/polynomial_identity_test.cc
#include "lib/crypto/polynomial_identity.h"
#include <gtest/gtest.h>

namespace f2chat {
namespace {

TEST(PolynomialIdentityTest, CreateSuccess) {
  auto result = PolynomialIdentity::Create("alice@example.com", "password123");
  ASSERT_TRUE(result.ok()) << result.status();

  auto identity = std::move(result).value();

  EXPECT_EQ(identity.real_identity(), "alice@example.com");

  // Polynomial ID should be non-zero
  auto poly = identity.polynomial_id();
  auto coeffs = poly.Decode();

  bool has_nonzero = false;
  for (auto coeff : coeffs) {
    if (coeff != 0) {
      has_nonzero = true;
      break;
    }
  }
  EXPECT_TRUE(has_nonzero) << "Polynomial ID should be non-zero (random)";
}

TEST(PolynomialIdentityTest, CreateEmptyIdentityFails) {
  auto result = PolynomialIdentity::Create("", "password");

  EXPECT_FALSE(result.ok());
  EXPECT_EQ(result.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST(PolynomialIdentityTest, CreateEmptyPasswordFails) {
  auto result = PolynomialIdentity::Create("alice", "");

  EXPECT_FALSE(result.ok());
  EXPECT_EQ(result.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST(PolynomialIdentityTest, PolynomialIDIsUnlinkable) {
  auto identity1 = PolynomialIdentity::Create("alice", "pw").value();
  auto identity2 = PolynomialIdentity::Create("alice", "pw").value();

  // Same real identity, different polynomial IDs (unlinkable)
  EXPECT_NE(identity1.polynomial_id(), identity2.polynomial_id());
}

TEST(PolynomialIdentityTest, RotatePolynomialID) {
  auto identity = PolynomialIdentity::Create("alice", "pw").value();

  auto old_poly = identity.polynomial_id();

  ASSERT_TRUE(identity.RotatePolynomialID().ok());

  auto new_poly = identity.polynomial_id();

  // Old and new should be different (unlinkable)
  EXPECT_NE(old_poly, new_poly);
}

TEST(PolynomialIdentityTest, AddContact) {
  auto alice = PolynomialIdentity::Create("alice", "pw").value();
  auto bob = PolynomialIdentity::Create("bob", "pw").value();

  // Alice adds Bob's polynomial as contact
  ASSERT_TRUE(alice.AddContact("Bob", bob.polynomial_id()).ok());

  // Lookup should succeed
  auto lookup = alice.LookupContactPolynomial("Bob");
  ASSERT_TRUE(lookup.ok());

  EXPECT_EQ(lookup.value(), bob.polynomial_id());
}

TEST(PolynomialIdentityTest, AddContactEmptyNameFails) {
  auto alice = PolynomialIdentity::Create("alice", "pw").value();
  Polynomial dummy({1, 2, 3});

  auto result = alice.AddContact("", dummy);

  EXPECT_FALSE(result.ok());
  EXPECT_EQ(result.code(), absl::StatusCode::kInvalidArgument);
}

TEST(PolynomialIdentityTest, LookupContactNotFound) {
  auto alice = PolynomialIdentity::Create("alice", "pw").value();

  auto result = alice.LookupContactPolynomial("Bob");

  EXPECT_FALSE(result.ok());
  EXPECT_EQ(result.status().code(), absl::StatusCode::kNotFound);
}

TEST(PolynomialIdentityTest, RemoveContact) {
  auto alice = PolynomialIdentity::Create("alice", "pw").value();
  Polynomial bob_poly({1, 2, 3});

  ASSERT_TRUE(alice.AddContact("Bob", bob_poly).ok());

  // Should exist
  EXPECT_TRUE(alice.LookupContactPolynomial("Bob").ok());

  // Remove
  ASSERT_TRUE(alice.RemoveContact("Bob").ok());

  // Should not exist
  EXPECT_FALSE(alice.LookupContactPolynomial("Bob").ok());
}

TEST(PolynomialIdentityTest, RemoveContactNotFoundFails) {
  auto alice = PolynomialIdentity::Create("alice", "pw").value();

  auto result = alice.RemoveContact("Bob");

  EXPECT_FALSE(result.ok());
  EXPECT_EQ(result.code(), absl::StatusCode::kNotFound);
}

TEST(PolynomialIdentityTest, ListContacts) {
  auto alice = PolynomialIdentity::Create("alice", "pw").value();

  // Initially empty
  EXPECT_EQ(alice.ListContacts().size(), 0);

  // Add contacts
  ASSERT_TRUE(alice.AddContact("Bob", Polynomial({1})).ok());
  ASSERT_TRUE(alice.AddContact("Carol", Polynomial({2})).ok());
  ASSERT_TRUE(alice.AddContact("Dave", Polynomial({3})).ok());

  auto contacts = alice.ListContacts();
  EXPECT_EQ(contacts.size(), 3);

  // Should contain all names (order may vary)
  bool has_bob = false, has_carol = false, has_dave = false;
  for (const auto& name : contacts) {
    if (name == "Bob") has_bob = true;
    if (name == "Carol") has_carol = true;
    if (name == "Dave") has_dave = true;
  }

  EXPECT_TRUE(has_bob);
  EXPECT_TRUE(has_carol);
  EXPECT_TRUE(has_dave);
}

TEST(PolynomialIdentityTest, OverwriteContact) {
  auto alice = PolynomialIdentity::Create("alice", "pw").value();

  Polynomial poly1({1, 2, 3});
  Polynomial poly2({4, 5, 6});

  ASSERT_TRUE(alice.AddContact("Bob", poly1).ok());

  // Overwrite with new polynomial
  ASSERT_TRUE(alice.AddContact("Bob", poly2).ok());

  auto lookup = alice.LookupContactPolynomial("Bob");
  ASSERT_TRUE(lookup.ok());

  EXPECT_EQ(lookup.value(), poly2);
}

}  // namespace
}  // namespace f2chat
