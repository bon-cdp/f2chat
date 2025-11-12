// lib/crypto/polynomial_params.h
//
// Configurable ring parameters for polynomial operations.
//
// Allows switching between safe (local testing) and production parameters.

#ifndef F2CHAT_LIB_CRYPTO_POLYNOMIAL_PARAMS_H_
#define F2CHAT_LIB_CRYPTO_POLYNOMIAL_PARAMS_H_

#include <cstdint>

namespace f2chat {

// Parameter sets for different use cases.

// SAFE: For local testing (won't crash your computer!)
// - Degree: 64 (enough for ~10-100 users)
// - Characters: 8 (reasonable for wreath product)
// - Memory: ~4 KB per operation
struct SafeParams {
  static constexpr int kDegree = 64;
  static constexpr int64_t kModulus = 65537;
  static constexpr int kNumCharacters = 8;
};

// MEDIUM: For small networks (100-1000 users)
// - Degree: 256
// - Characters: 16
// - Memory: ~32 KB per operation
struct MediumParams {
  static constexpr int kDegree = 256;
  static constexpr int64_t kModulus = 65537;
  static constexpr int kNumCharacters = 16;
};

// PRODUCTION: For large networks (requires GPU/cluster)
// - Degree: 4096
// - Characters: 64
// - Memory: ~2 MB per operation
struct ProductionParams {
  static constexpr int kDegree = 4096;
  static constexpr int64_t kModulus = 65537;
  static constexpr int kNumCharacters = 64;
};

// Active parameter set (change this to switch modes)
#ifdef F2CHAT_PRODUCTION_MODE
using RingParams = ProductionParams;
#elif defined(F2CHAT_MEDIUM_MODE)
using RingParams = MediumParams;
#else
using RingParams = SafeParams;  // Default: SAFE
#endif

}  // namespace f2chat

#endif  // F2CHAT_LIB_CRYPTO_POLYNOMIAL_PARAMS_H_
