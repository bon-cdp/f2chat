// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#include "lib/crypto/fhe_operations.h"

#include <cmath>
#include <cstdint>
#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"

// OpenFHE includes
#include "openfhe.h"

namespace f2chat {

// ===== FheOperations Implementation =====

absl::StatusOr<lbcrypto::Ciphertext> FheOperations::EvalSumAllSlots(
    const lbcrypto::Ciphertext& ciphertext,
    int slot_count) {
  if (!ciphertext) {
    return absl::InvalidArgumentError("Ciphertext is null");
  }

  if (slot_count <= 0 || (slot_count & (slot_count - 1)) != 0) {
    return absl::InvalidArgumentError(
        absl::StrCat("slot_count must be power of 2, got ", slot_count));
  }

  auto ctx = ciphertext->GetCryptoContext();
  if (!ctx) {
    return absl::InternalError("Crypto context is null");
  }

  try {
    // Halevi-Shoup binary tree reduction
    // After k steps, each slot contains sum of 2^k consecutive original slots
    //
    // Example (8 slots):
    // Start:    [a, b, c, d, e, f, g, h]
    // Step 1:   [a+b, b+c, c+d, d+e, e+f, f+g, g+h, h+a]  (rotate 1)
    // Step 2:   [a+b+c+d, ..., ..., ...]                  (rotate 2)
    // Step 3:   [a+b+c+d+e+f+g+h, ..., ...]              (rotate 4)
    // Result: slot 0 contains sum of all slots

    auto result = ciphertext;

    for (int step = 1; step < slot_count; step *= 2) {
      // Rotate right by 'step' positions
      auto rotated = ctx->EvalRotate(result, step);

      // Add rotated to accumulator
      result = ctx->EvalAdd(result, rotated);
    }

    // Now result[0] contains the sum of all original slots
    return result;

  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrCat("EvalSumAllSlots failed: ", e.what()));
  }
}

absl::StatusOr<lbcrypto::Ciphertext> FheOperations::BroadcastToAllSlots(
    const lbcrypto::Ciphertext& single_value,
    int slot_count) {
  if (!single_value) {
    return absl::InvalidArgumentError("Ciphertext is null");
  }

  if (slot_count <= 0 || (slot_count & (slot_count - 1)) != 0) {
    return absl::InvalidArgumentError(
        absl::StrCat("slot_count must be power of 2, got ", slot_count));
  }

  auto ctx = single_value->GetCryptoContext();
  if (!ctx) {
    return absl::InternalError("Crypto context is null");
  }

  try {
    // Broadcasting is similar to reduction but uses doubling:
    // Start:    [v, 0, 0, 0, 0, 0, 0, 0]
    // Step 1:   [v, v, 0, 0, 0, 0, 0, 0]  (rotate -1, add)
    // Step 2:   [v, v, v, v, 0, 0, 0, 0]  (rotate -2, add)
    // Step 3:   [v, v, v, v, v, v, v, v]  (rotate -4, add)

    auto result = single_value;

    for (int step = 1; step < slot_count; step *= 2) {
      // Rotate left by 'step' (negative rotation index)
      auto rotated = ctx->EvalRotate(result, -step);

      // Add to fill more slots
      result = ctx->EvalAdd(result, rotated);
    }

    // Now all slots contain the value from slot 0
    return result;

  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrCat("BroadcastToAllSlots failed: ", e.what()));
  }
}

absl::StatusOr<lbcrypto::Ciphertext> FheOperations::EvalEqual(
    const lbcrypto::Ciphertext& a,
    const lbcrypto::Ciphertext& b,
    uint64_t plaintext_modulus) {
  if (!a || !b) {
    return absl::InvalidArgumentError("Ciphertext is null");
  }

  if (plaintext_modulus < 2) {
    return absl::InvalidArgumentError(
        "plaintext_modulus must be >= 2 (should be prime)");
  }

  auto ctx = a->GetCryptoContext();
  if (!ctx) {
    return absl::InternalError("Crypto context is null");
  }

  // Verify both ciphertexts use same context
  if (a->GetCryptoContext() != b->GetCryptoContext()) {
    return absl::InvalidArgumentError(
        "Ciphertexts must use same crypto context");
  }

  try {
    // Algorithm: (a == b) implemented as 1 - (a - b)^(p-1) mod p
    //
    // By Fermat's Little Theorem:
    //   For prime p and any x ∈ ℤₚ:
    //     x^(p-1) ≡ 1 (mod p)  if x ≠ 0
    //     0^(p-1) ≡ 0 (mod p)  if x = 0
    //
    // So: (a - b)^(p-1) = 0 iff a = b
    //     1 - (a - b)^(p-1) = 1 iff a = b, else 0

    // Step 1: Compute difference
    auto diff = ctx->EvalSub(a, b);

    // Step 2: Raise to power (p-1) using binary exponentiation
    // For p = 65537, exponent = 65536 = 2^16
    // Binary exponentiation: O(log exponent) multiplications
    uint64_t exponent = plaintext_modulus - 1;

    // Check if OpenFHE provides EvalPower (some versions do)
    // If not available, we'll implement binary exponentiation manually

    lbcrypto::Ciphertext powered;

#ifdef OPENFHE_HAS_EVAL_POWER
    // Use built-in if available (faster, optimized)
    powered = ctx->EvalPower(diff, exponent);
#else
    // Manual binary exponentiation
    // Example: To compute x^13 = x^(1101₂)
    // Result = x^1 * x^4 * x^8 = x^13
    //
    // Loop through bits of exponent from MSB to LSB
    powered = diff;  // Start with x^1
    uint64_t remaining = exponent - 1;  // Already have x^1

    while (remaining > 0) {
      // Square current result
      powered = ctx->EvalMult(powered, powered);

      // If current bit is 1, multiply by base
      if (remaining & 1) {
        powered = ctx->EvalMult(powered, diff);
      }

      remaining >>= 1;  // Move to next bit
    }
#endif

    // Step 3: Compute 1 - powered to flip result
    // (a - b)^(p-1) = 0 if equal, = 1 if not equal
    // We want: 1 if equal, 0 if not equal
    // So compute: 1 - (a - b)^(p-1)

    // Create plaintext with 1 in all slots
    std::vector<int64_t> ones(8192, 1);  // Assume 8192 slots (TODO: Get from context)
    auto ones_plaintext = ctx->MakePackedPlaintext(ones);

    // Subtract: 1 - powered
    auto result = ctx->EvalSub(ones_plaintext, powered);

    return result;

  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrCat("EvalEqual failed: ", e.what()));
  }
}

absl::StatusOr<lbcrypto::Ciphertext> FheOperations::ExtractSlot(
    const lbcrypto::Ciphertext& ciphertext,
    int slot_index,
    int slot_count) {
  if (!ciphertext) {
    return absl::InvalidArgumentError("Ciphertext is null");
  }

  if (slot_index < 0 || slot_index >= slot_count) {
    return absl::InvalidArgumentError(
        absl::StrCat("slot_index ", slot_index, " out of range [0, ",
                     slot_count, ")"));
  }

  auto ctx = ciphertext->GetCryptoContext();
  if (!ctx) {
    return absl::InternalError("Crypto context is null");
  }

  try {
    // Create mask: 1 at slot_index, 0 elsewhere
    std::vector<int64_t> mask(slot_count, 0);
    mask[slot_index] = 1;

    auto mask_plaintext = ctx->MakePackedPlaintext(mask);

    // Multiply ciphertext by mask to extract single slot
    auto result = ctx->EvalMult(ciphertext, mask_plaintext);

    return result;

  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrCat("ExtractSlot failed: ", e.what()));
  }
}

}  // namespace f2chat
