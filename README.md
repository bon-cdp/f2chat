# f2chat

**FHE-based encrypted messaging with cross-user spam detection using SIMD batching**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview

f2chat is an asynchronous messaging protocol that uses **Fully Homomorphic Encryption (FHE)** to enable server-side spam detection across encrypted messages—something traditional End-to-End Encryption (E2EE) fundamentally cannot do.

### The Problem

Current encrypted messengers (Signal, WhatsApp, Matrix) suffer from spam campaigns because servers are blind to message content:
- ❌ **Cannot detect:** "Same message sent to 10,000 users" (content-based spam campaigns)
- ❌ **Cannot detect:** "50 bots sent similar message variants" (coordinated attacks)
- ✅ **Can only detect:** Metadata patterns (frequency, timing, sender reputation)

### The Solution

f2chat uses **FHE with SIMD batching** to enable cross-user spam detection:
- ✅ **Server computes on encrypted messages** without ever seeing plaintext
- ✅ **Detect duplicate messages** across thousands of users (Private Set Intersection)
- ✅ **Detect similar messages** using encrypted edit distance (Leuvenshtein algorithm)
- ✅ **Scalable:** Process 8,192 messages with 1 FHE operation (SIMD batching)
- ✅ **User control:** Clients decide how to handle spam alerts (not server censorship)

## Architecture

### Technology Stack

- **Language:** C++20 (Google C++ Style Guide)
- **FHE Library:** [OpenFHE](https://github.com/openfheorg/openfhe-development) (BGV scheme, 8192 slots, 128-bit security)
- **Compiler:** [HEIR](https://heir.dev/) (Google's MLIR-based FHE compiler with automatic SIMD optimization)
- **Build System:** Bazel
- **Testing:** GoogleTest

### Key Components

```
lib/
├── crypto/       # FHE operations (FheContext, key management)
├── message/      # Message representation (EncryptedMessage)
├── simd/         # SIMD batching (SimdBatch, cross-user operations)
└── util/         # Utilities (status codes, logging)
```

### How It Works

1. **Client encrypts message** using FHE (BGV, OpenFHE)
2. **Server batches messages** into SIMD ciphertexts (8192 messages per batch)
3. **Server detects patterns:**
   - **Duplicates:** Private Set Intersection (PSI) on encrypted messages
   - **Similar messages:** Edit distance using Leuvenshtein algorithm (278× faster than naive)
4. **Server sends alerts** to affected clients
5. **Clients decide:** Quarantine? Show warning? Ignore?

**Example:**
```
Bot A → "Click here for free Bitcoin! Link: bit.ly/scam1"
Bot B → "Click here for free Ethereum! Link: bit.ly/scam2"
Bot C → "Click here for free Dogecoin! Link: bit.ly/scam3"

Server (on encrypted messages):
- Computes edit distance in parallel (SIMD batching)
- Detects: "50 messages are 90%+ similar"
- Alert: "Suspected coordinated spam campaign"
```

## Performance

### SIMD Batching Speedup

- **Without batching:** Compare each message to all others → O(N²) operations
- **With SIMD (8192 slots):** Batch messages, parallel comparison → **5,000-10,000× speedup**

### Projected Throughput

- **1,000 messages/hour:** ~12ms server CPU time
- **10,000 messages/hour:** ~120ms server CPU time
- **100,000 messages/hour:** ~1.2s server CPU time
- **With GPU (H100):** Millions of messages/hour

### Benchmarks (Goals)

- ✅ Encrypt 1 message: <100ms (client)
- ✅ Detect duplicates (8192-message batch): <5s (server)
- ✅ Edit distance (256-char messages): <100ms per pair (server)
- ✅ End-to-end latency: <15s (send → spam check → deliver)

## Building

### Prerequisites

- Bazel 7.0+
- C++20 compiler (GCC 11+, Clang 14+)
- OpenFHE (fetched automatically by Bazel)

### Build

```bash
# Build all targets
bazel build //...

# Run tests
bazel test //...

# Run benchmarks
bazel run //benchmarks:crypto_benchmark
```

## Development Status

**Phase 1: Foundation (Current)**
- [x] Project structure
- [x] Bazel build system
- [ ] FheContext (BGV, 8192 slots, 128-bit security)
- [ ] EncryptedMessage (ciphertext + signature + metadata)
- [ ] SimdBatch (SIMD packing/unpacking)
- [ ] Unit tests (GoogleTest)

**Phase 2: HEIR Integration** (Planned)
- [ ] HEIR Python frontend (duplicate detection)
- [ ] SIMD optimization (rotation minimization)
- [ ] SpamDetector (PSI-based)

**Phase 3: Similarity Detection** (Planned)
- [ ] Leuvenshtein edit distance (HEIR-compiled)
- [ ] Clustering algorithm (coordinated campaigns)

**Phase 4: Server & Client** (Planned)
- [ ] gRPC server (message ingestion, batching)
- [ ] CLI client (full UX)

**Phase 5: Documentation & Release** (Planned)
- [ ] Research paper (USENIX Security, CCS, NDSS)
- [ ] Public release, community engagement

## Research

f2chat is a research project demonstrating the feasibility of FHE for real-world spam detection. Key innovations:

- **SIMD batching for scalability:** Process thousands of encrypted messages in parallel
- **Cross-user pattern detection:** Detect spam campaigns that E2EE cannot
- **HEIR optimization:** Automatic rotation minimization (72-179× speedup)
- **Privacy-preserving spam filtering:** Server never sees plaintext

### Publications

- Research paper: *In preparation*
- Target venues: USENIX Security, ACM CCS, NDSS

## Contributing

Contributions welcome! This project follows the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html).

### Code Review Standards (HEIR-level rigor)

- ✅ Minimal, elegant abstractions
- ✅ Extensive testing (unit, integration, benchmarks)
- ✅ Clear separation of concerns
- ✅ Performance-conscious (every FHE operation must be justified)
- ✅ Security rigor (threat model, formal verification where possible)
- ✅ Comprehensive documentation

## License

Apache 2.0 - See [LICENSE](LICENSE)

## References

- [OpenFHE](https://github.com/openfheorg/openfhe-development) - FHE library
- [HEIR](https://heir.dev/) - Google's FHE compiler
- [HElib Paper](https://www.shoup.net/papers/helib.pdf) - SIMD batching foundations
- [Fast PSI from FHE](https://www.microsoft.com/en-us/research/publication/fast-private-set-intersection-homomorphic-encryption/) - Microsoft Research, 2017
- [Leuvenshtein Algorithm](https://eprint.iacr.org/2025/012.pdf) - USENIX Security 2025

## Contact

- GitHub Issues: [https://github.com/bon-cdp/f2chat/issues](https://github.com/bon-cdp/f2chat/issues)
- Discussions: [https://github.com/bon-cdp/f2chat/discussions](https://github.com/bon-cdp/f2chat/discussions)

---

*f2chat is a proof-of-concept research project, not production-ready software.*
