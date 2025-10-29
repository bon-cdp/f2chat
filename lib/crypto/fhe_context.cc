// Copyright 2025 f2chat Contributors
// Licensed under the Apache License, Version 2.0

#include "lib/crypto/fhe_context.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"

// OpenFHE includes
#include "openfhe.h"

namespace f2chat {

// ===== FheContext Implementation =====

FheContext::FheContext(const FheParameters& params,
                       lbcrypto::CryptoContext context)
    : params_(params), context_(std::move(context)) {}

FheContext::~FheContext() = default;

absl::StatusOr<std::unique_ptr<FheContext>> FheContext::Create(
    const FheParameters& params) {
  // Validate parameters
  if (params.security_level < 128) {
    return absl::InvalidArgumentError(
        "Security level must be at least 128 bits");
  }
  if (params.polynomial_degree < 1024 || params.polynomial_degree > 65536) {
    return absl::InvalidArgumentError(
        "Polynomial degree must be between 1024 and 65536");
  }
  if (params.slot_count != params.polynomial_degree / 2) {
    return absl::InvalidArgumentError(
        absl::StrCat("Slot count must be polynomial_degree/2 (expected ",
                     params.polynomial_degree / 2, ", got ", params.slot_count, ")"));
  }

  // Configure OpenFHE parameters for BGV scheme
  lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS> parameters;

  // Set plaintext modulus (for integer arithmetic)
  parameters.SetPlaintextModulus(params.plaintext_modulus);

  // Set multiplicative depth
  parameters.SetMultiplicativeDepth(params.multiplicative_depth);

  // Set security level (128-bit standard)
  parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);

  // Set polynomial degree (ring dimension)
  parameters.SetRingDim(params.polynomial_degree);

  // Set batching (SIMD) - enable for slot-based operations
  parameters.SetBatchSize(params.slot_count);

  // Set key switching technique
  switch (params.key_switch_technique) {
    case FheParameters::KeySwitchTechnique::BV:
      parameters.SetKeySwitchTechnique(lbcrypto::KeySwitchTechnique::BV);
      break;
    case FheParameters::KeySwitchTechnique::HYBRID:
      parameters.SetKeySwitchTechnique(lbcrypto::KeySwitchTechnique::HYBRID);
      break;
    case FheParameters::KeySwitchTechnique::GHS:
      // Note: GHS not directly supported in all OpenFHE versions
      // Fall back to HYBRID
      parameters.SetKeySwitchTechnique(lbcrypto::KeySwitchTechnique::HYBRID);
      break;
  }

  // Create OpenFHE crypto context
  lbcrypto::CryptoContext context;
  try {
    context = lbcrypto::GenCryptoContext(parameters);
  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrCat("Failed to create OpenFHE context: ", e.what()));
  }

  if (!context) {
    return absl::InternalError("OpenFHE context is null after creation");
  }

  // Enable features
  try {
    context->Enable(lbcrypto::PKESchemeFeature::PKE);          // Basic encryption
    context->Enable(lbcrypto::PKESchemeFeature::KEYSWITCH);    // Key switching
    context->Enable(lbcrypto::PKESchemeFeature::LEVELEDSHE);   // Leveled SHE
    context->Enable(lbcrypto::PKESchemeFeature::ADVANCEDSHE);  // Advanced ops (rotation)
  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrCat("Failed to enable OpenFHE features: ", e.what()));
  }

  // Create FheContext (use unique_ptr for ownership)
  return std::unique_ptr<FheContext>(new FheContext(params, context));
}

absl::StatusOr<KeyPair> FheContext::GenerateKeys() const {
  KeyPair keypair;

  try {
    // Generate public/private key pair
    auto openfhe_keypair = context_->KeyGen();
    keypair.public_key = openfhe_keypair.publicKey;
    keypair.private_key = openfhe_keypair.secretKey;

    // Generate evaluation keys for homomorphic operations
    // Multiplication key (required for homomorphic multiplication)
    context_->EvalMultKeyGen(keypair.private_key);

    // Rotation keys (required for SIMD slot rotations)
    // Generate keys for all possible rotation indices
    std::vector<int32_t> rotation_indices;
    for (int i = 1; i < params_.slot_count; i *= 2) {
      rotation_indices.push_back(i);
      rotation_indices.push_back(-i);
    }
    context_->EvalRotateKeyGen(keypair.private_key, rotation_indices);

    // Note: Evaluation keys are stored in the context, not returned explicitly
    // They're accessed automatically during homomorphic operations

  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrCat("Failed to generate keys: ", e.what()));
  }

  return keypair;
}

absl::StatusOr<std::shared_ptr<lbcrypto::Ciphertext>> FheContext::Encrypt(
    const std::string& plaintext,
    const PublicKey& public_key) const {
  // Convert string to vector of integers (ASCII values)
  std::vector<int64_t> plaintext_values;
  plaintext_values.reserve(plaintext.size());
  for (char c : plaintext) {
    plaintext_values.push_back(static_cast<int64_t>(static_cast<unsigned char>(c)));
  }

  // Pad to slot count with zeros
  plaintext_values.resize(params_.slot_count, 0);

  // Use EncryptVector for actual encryption
  return EncryptVector(plaintext_values, public_key);
}

absl::StatusOr<std::shared_ptr<lbcrypto::Ciphertext>> FheContext::EncryptVector(
    const std::vector<int64_t>& plaintext,
    const PublicKey& public_key) const {
  if (plaintext.size() > static_cast<size_t>(params_.slot_count)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Plaintext size (", plaintext.size(),
                     ") exceeds slot count (", params_.slot_count, ")"));
  }

  try {
    // Create OpenFHE plaintext (packed in SIMD slots)
    auto openfhe_plaintext = context_->MakePackedPlaintext(plaintext);

    // Encrypt
    auto ciphertext = context_->Encrypt(public_key.key(), openfhe_plaintext);

    if (!ciphertext) {
      return absl::InternalError("Encryption resulted in null ciphertext");
    }

    return ciphertext;

  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrCat("Failed to encrypt: ", e.what()));
  }
}

absl::StatusOr<std::string> FheContext::Decrypt(
    const std::shared_ptr<lbcrypto::Ciphertext>& ciphertext,
    const SecretKey& secret_key) const {
  // Decrypt to vector
  auto plaintext_vector_or = DecryptVector(ciphertext, secret_key);
  if (!plaintext_vector_or.ok()) {
    return plaintext_vector_or.status();
  }

  // Convert vector of integers back to string
  const auto& plaintext_values = plaintext_vector_or.value();
  std::string plaintext;
  plaintext.reserve(plaintext_values.size());

  for (int64_t value : plaintext_values) {
    if (value == 0) break;  // Stop at first null terminator
    if (value < 0 || value > 255) {
      return absl::InternalError(
          absl::StrCat("Invalid ASCII value after decryption: ", value));
    }
    plaintext.push_back(static_cast<char>(value));
  }

  return plaintext;
}

absl::StatusOr<std::vector<int64_t>> FheContext::DecryptVector(
    const std::shared_ptr<lbcrypto::Ciphertext>& ciphertext,
    const SecretKey& secret_key) const {
  if (!ciphertext) {
    return absl::InvalidArgumentError("Ciphertext is null");
  }

  try {
    // Decrypt
    lbcrypto::Plaintext plaintext;
    context_->Decrypt(secret_key.key(), ciphertext, &plaintext);

    if (!plaintext) {
      return absl::InternalError("Decryption resulted in null plaintext");
    }

    // Extract values from SIMD slots
    const auto& packed_values = plaintext->GetPackedValue();

    // Convert to int64_t vector
    std::vector<int64_t> result;
    result.reserve(packed_values.size());
    for (const auto& value : packed_values) {
      result.push_back(value.ConvertToInt());
    }

    return result;

  } catch (const std::exception& e) {
    return absl::InternalError(
        absl::StrCat("Failed to decrypt: ", e.what()));
  }
}

}  // namespace f2chat
