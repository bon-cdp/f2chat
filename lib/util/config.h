// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#ifndef F2CHAT_LIB_UTIL_CONFIG_H_
#define F2CHAT_LIB_UTIL_CONFIG_H_

#include <cstdint>

namespace f2chat {

// FHE cryptographic parameters (BGV scheme)
struct FheParameters {
  // Security level in bits (128 = standard security)
  int security_level = 128;

  // Polynomial degree (N in RLWE)
  // 16384 supports 8192 slots with batching
  int polynomial_degree = 16384;

  // Plaintext modulus (for BGV integer arithmetic)
  // Large prime for full slot utilization
  uint64_t plaintext_modulus = 65537;

  // Multiplicative depth (how many multiplications before bootstrapping)
  int multiplicative_depth = 10;

  // Number of SIMD slots for batching
  // For polynomial degree N, slots = N/2
  int slot_count = 8192;

  // Key switching technique
  // HYBRID is recommended for BGV (balance between key size and performance)
  enum class KeySwitchTechnique {
    BV,      // Brakerski-Vaikuntanathan
    HYBRID,  // Hybrid (recommended)
    GHS      // Gentry-Halevi-Smart
  };
  KeySwitchTechnique key_switch_technique = KeySwitchTechnique::HYBRID;
};

}  // namespace f2chat

#endif  // F2CHAT_LIB_UTIL_CONFIG_H_
