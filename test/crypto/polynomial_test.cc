// test/crypto/polynomial_test.cc
#include "lib/crypto/polynomial.h"
#include <gtest/gtest.h>

namespace f2chat {
namespace {

TEST(PolynomialTest, DefaultConstructor) {
  Polynomial p;
  auto coeffs = p.Decode();

  EXPECT_EQ(coeffs.size(), RingParams::kDegree);

  // All coefficients should be zero
  for (auto coeff : coeffs) {
    EXPECT_EQ(coeff, 0);
  }
}

TEST(PolynomialTest, ConstructFromCoefficients) {
  std::vector<int64_t> coeffs = {1, 2, 3, 4, 5};
  Polynomial p(coeffs);

  auto decoded = p.Decode();
  EXPECT_EQ(decoded[0], 1);
  EXPECT_EQ(decoded[1], 2);
  EXPECT_EQ(decoded[2], 3);
  EXPECT_EQ(decoded[3], 4);
  EXPECT_EQ(decoded[4], 5);
}

TEST(PolynomialTest, AddCommutative) {
  Polynomial p1({1, 2, 3});
  Polynomial p2({4, 5, 6});

  auto sum1 = p1.Add(p2);
  auto sum2 = p2.Add(p1);

  EXPECT_EQ(sum1, sum2);

  auto coeffs = sum1.Decode();
  EXPECT_EQ(coeffs[0], 5);
  EXPECT_EQ(coeffs[1], 7);
  EXPECT_EQ(coeffs[2], 9);
}

TEST(PolynomialTest, SubtractCorrect) {
  Polynomial p1({10, 20, 30});
  Polynomial p2({3, 5, 7});

  auto diff = p1.Subtract(p2);
  auto coeffs = diff.Decode();

  EXPECT_EQ(coeffs[0], 7);
  EXPECT_EQ(coeffs[1], 15);
  EXPECT_EQ(coeffs[2], 23);
}

TEST(PolynomialTest, MultiplyScalar) {
  Polynomial p({1, 2, 3});
  auto scaled = p.MultiplyScalar(5);

  auto coeffs = scaled.Decode();
  EXPECT_EQ(coeffs[0], 5);
  EXPECT_EQ(coeffs[1], 10);
  EXPECT_EQ(coeffs[2], 15);
}

TEST(PolynomialTest, Rotate) {
  Polynomial p({1, 2, 3, 0, 0});  // Rest zeros

  // Rotate right by 1
  auto rotated = p.Rotate(1);
  auto coeffs = rotated.Decode();

  // Last element moves to front (circular)
  EXPECT_EQ(coeffs[0], 0);
  EXPECT_EQ(coeffs[1], 1);
  EXPECT_EQ(coeffs[2], 2);
  EXPECT_EQ(coeffs[3], 3);
}

TEST(PolynomialTest, Negate) {
  Polynomial p({1, 2, 3});
  auto negated = p.Negate();

  auto coeffs = negated.Decode();

  // Should be: -1, -2, -3 mod p
  EXPECT_EQ(coeffs[0], RingParams::kModulus - 1);
  EXPECT_EQ(coeffs[1], RingParams::kModulus - 2);
  EXPECT_EQ(coeffs[2], RingParams::kModulus - 3);
}

TEST(PolynomialTest, EncodeDecodeRoundtrip) {
  std::vector<int64_t> original = {42, 100, 256, 1024};

  auto poly_or = Polynomial::Encode(original);
  ASSERT_TRUE(poly_or.ok());

  auto poly = std::move(poly_or).value();
  auto decoded = poly.Decode();

  for (size_t i = 0; i < original.size(); ++i) {
    EXPECT_EQ(decoded[i], original[i]);
  }
}

TEST(PolynomialTest, EncodeTooManyValuesFails) {
  std::vector<int64_t> too_many(RingParams::kDegree + 1, 1);

  auto result = Polynomial::Encode(too_many);
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(result.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST(PolynomialTest, ProjectToCharacterValidIndex) {
  Polynomial p({1, 2, 3, 4, 5});

  auto proj_or = p.ProjectToCharacter(0);
  ASSERT_TRUE(proj_or.ok());

  // Projection should be a valid polynomial
  auto proj = std::move(proj_or).value();
  EXPECT_EQ(proj.Decode().size(), RingParams::kDegree);
}

TEST(PolynomialTest, ProjectToCharacterInvalidIndex) {
  Polynomial p({1, 2, 3});

  auto result = p.ProjectToCharacter(-1);
  EXPECT_FALSE(result.ok());

  auto result2 = p.ProjectToCharacter(RingParams::kNumCharacters);
  EXPECT_FALSE(result2.ok());
}

TEST(PolynomialTest, ProjectToAllCharacters) {
  Polynomial p({1, 2, 3, 4, 5});

  auto projections = p.ProjectToAllCharacters();

  EXPECT_EQ(projections.size(), RingParams::kNumCharacters);

  // Each projection should be valid
  for (const auto& proj : projections) {
    EXPECT_EQ(proj.Decode().size(), RingParams::kDegree);
  }
}

TEST(PolynomialTest, EqualityOperator) {
  Polynomial p1({1, 2, 3});
  Polynomial p2({1, 2, 3});
  Polynomial p3({1, 2, 4});

  EXPECT_EQ(p1, p2);
  EXPECT_NE(p1, p3);
}

TEST(PolynomialTest, AddSubtractInverse) {
  Polynomial p1({5, 10, 15});
  Polynomial p2({5, 10, 15});

  // p1 - p2 should be zero
  auto diff = p1.Subtract(p2);
  auto coeffs = diff.Decode();

  EXPECT_EQ(coeffs[0], 0);
  EXPECT_EQ(coeffs[1], 0);
  EXPECT_EQ(coeffs[2], 0);
}

TEST(PolynomialTest, ModulusReduction) {
  // Test that coefficients are properly reduced mod p
  std::vector<int64_t> large = {RingParams::kModulus + 5};
  Polynomial p(large);

  auto coeffs = p.Decode();
  EXPECT_EQ(coeffs[0], 5);  // Should wrap around
}

}  // namespace
}  // namespace f2chat
