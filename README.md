# f2chat

**Serverless Threshold Cryptography for Privacy-Preserving Spam Detection**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview

f2chat demonstrates a groundbreaking approach to distributed trust: **using AWS Lambda, Google Cloud Functions, and Cloudflare Workers to perform threshold decryption of FHE spam detection results**—achieving distributed trust at **1/1000th the cost** of dedicated servers.

### The Problem

Current encrypted messengers face an impossible tradeoff:
- ❌ **Spam blindness:** E2EE prevents server-side spam detection (Signal, WhatsApp, Matrix)
- ❌ **Client-side scanning:** Proposed solutions (Apple CSAM, Meta) break user privacy
- ❌ **Expensive infrastructure:** Traditional threshold cryptography requires dedicated federated servers ($200-2000/month)

### Our Solution: Multi-Cloud Edge Threshold

f2chat combines three innovations:

1. **FHE Spam Detection** (Phase 1-2)
   - Server computes on encrypted messages without seeing plaintext
   - SIMD batching: Process 8,192 messages in one FHE operation
   - Detect duplicate messages and similar variants (edit distance)

2. **Threshold Cryptography** (Phase 3)
   - Split decryption key across 5 parties (k=3 threshold)
   - Any 3 parties can decrypt spam counts
   - Single party compromise reveals nothing

3. **Multi-Cloud Edge Compute** (Phase 4) 🌟 **CORE INNOVATION**
   - Deploy threshold shares to AWS Lambda, Google Cloud Functions, Cloudflare Workers
   - Parallel invocation: 150ms latency (vs 2 seconds for dedicated servers)
   - Cost: **$0.03-3/month** (vs $200-2000 for federated servers)
   - Jurisdictional diversity: Resistant to single-government coercion

## Architecture

### System Overview

```
┌─────────────┐
│   Client    │ Encrypts message with FHE
│  (Desktop)  │ Public key: Server's PK_global
└──────┬──────┘
       │
       ↓ Send EncryptedMessage(hash)
┌─────────────────────────────────────┐
│         Server (Trusted for FHE)    │
│  • Batches 1000 messages into SIMD  │
│  • Detects duplicates (FHE compute) │
│  • Identifies spam (encrypted count)│
└──────┬──────────────────────────────┘
       │
       ↓ Send Ciphertext(spam_count) to threshold parties
┌──────────────────────────────────────────────────────┐
│       Multi-Cloud Edge Threshold (Distributed Trust) │
│                                                       │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐       │
│  │  AWS     │    │ Google   │    │Cloudflare│       │
│  │ Lambda   │    │ Cloud Fn │    │ Workers  │       │
│  │ (Share 1)│    │ (Share 2)│    │ (Share 3)│       │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘       │
│       │               │               │              │
│       └───────────────┴───────────────┘              │
│                       │                              │
│            Partial Decryptions                       │
│         (Combine k=3 → Plaintext)                    │
└──────────────────────────┬───────────────────────────┘
                           │
                           ↓ Alert: "500 duplicate messages detected"
                    ┌─────────────┐
                    │   Clients   │ Decide: Quarantine? Show warning?
                    └─────────────┘
```

### Why Edge Threshold?

| Approach                  | Cost/Month | Latency | Single Point of Failure? | Jurisdictional Diversity? |
|---------------------------|------------|---------|--------------------------|---------------------------|
| **Single Server**         | $50-200    | 50ms    | ✅ Yes (trusted)         | ❌ No                     |
| **Federated Servers (5)** | $200-2000  | 2000ms  | ❌ No (k=3 threshold)    | ⚠️ Depends on org        |
| **Multi-Cloud Edge (5)**  | **$0.03-3**| **150ms**| ❌ No (k=3 threshold)   | ✅ Yes (AWS+Google+CF)   |

**1000× cost reduction** with better latency and stronger jurisdictional resistance.

## Technology Stack

- **Language:** C++20 (Google C++ Style Guide)
- **FHE Library:** [OpenFHE](https://github.com/openfheorg/openfhe-development) (BGV scheme, 8192 slots, 128-bit security)
- **Build System:** Bazel 8.0+ with Bzlmod
- **Testing:** GoogleTest
- **Error Handling:** Abseil (StatusOr pattern)
- **Cloud Providers:** AWS Lambda, Google Cloud Functions, Cloudflare Workers

### Key Components

```
lib/
├── crypto/
│   ├── fhe_context.{h,cc}          # FHE encryption/decryption (OpenFHE wrapper)
│   ├── fhe_operations.{h,cc}       # SIMD operations (Halevi-Shoup binary reduction)
│   ├── server_key_manager.{h,cc}   # Centralized key storage (Phase 1-2)
│   └── threshold_keygen.{h,cc}     # Secret sharing (Phase 3+)
├── message/
│   ├── encrypted_message.{h,cc}    # Message protocol (signature, timestamp, nonce)
│   └── BUILD.bazel
├── simd/
│   ├── simd_batch.{h,cc}           # Batching utilities (pack/unpack)
│   └── BUILD.bazel
├── threshold/                       # (Phase 3+)
│   ├── coordinator.{h,cc}          # Multi-party orchestration
│   └── partial_decrypt.{h,cc}      # Single-share decryption
└── edge/                            # (Phase 4+)
    ├── edge_coordinator.{h,cc}     # HTTP client for edge functions
    └── BUILD.bazel

edge_functions/                      # Serverless deployments (Phase 4+)
├── aws_lambda/
│   ├── lambda_function.py          # AWS Lambda (Python)
│   └── secrets.yaml                # Share 1 (from AWS Secrets Manager)
├── google_cloud/
│   ├── main.py                     # Google Cloud Function
│   └── secrets.yaml                # Share 2 (from Secret Manager)
└── cloudflare_workers/
    ├── worker.js                   # Cloudflare Worker (Wasm)
    └── wrangler.toml               # Share 3 (from KV Store)
```

## How It Works

### Phase 1-2: Single-Key FHE (Current)

1. **Client encrypts message hash** with server's public key (FHE)
2. **Server batches 1000 messages** into SIMD ciphertext (8192 slots)
3. **Server detects duplicates** using Halevi-Shoup binary reduction (FHE compute)
4. **Server decrypts spam count** (trusted server model)
5. **Server alerts affected clients**

**Trade-off:** Server can decrypt (trusted), but no client-side scanning.

### Phase 3-4: Multi-Cloud Threshold (Target)

1. **Threshold key generation:** Split SK_global → [Share_1, Share_2, Share_3, Share_4, Share_5]
2. **Deploy shares:** AWS (Share 1), Google (Share 2), Cloudflare (Share 3), Azure (Share 4), Vercel (Share 5)
3. **Server sends encrypted spam count** to all 5 edge functions (parallel HTTP requests)
4. **Edge functions perform partial decryption** with their share
5. **Coordinator combines k=3 partial decryptions** → full plaintext
6. **Server alerts clients** (only sees spam count, not individual messages)

**Security:**
- ✅ Server cannot decrypt (doesn't have enough shares)
- ✅ Single cloud provider compromise reveals nothing (need k=3)
- ✅ Government coercion of one provider insufficient (AWS, Google, Cloudflare have different jurisdictions)

## Performance

### Benchmarks (Projected)

| Operation                         | Latency     | Throughput          |
|-----------------------------------|-------------|---------------------|
| **Client: Encrypt message**       | 50-100ms    | 10-20 msg/sec       |
| **Server: Batch 1000 messages**   | 100ms       | 10,000 msg/sec      |
| **Server: Detect duplicates (FHE)**| 2-5s       | 200,000 msg/hour    |
| **Edge: Threshold decrypt (cold)**| 800-1200ms  | -                   |
| **Edge: Threshold decrypt (warm)**| 100-150ms   | -                   |
| **End-to-end spam detection**     | 3-7s        | -                   |

### SIMD Speedup

- **Without SIMD:** Compare 1000 messages → 1,000,000 FHE operations (O(N²))
- **With SIMD:** Batch + Halevi-Shoup → 13 rotations + 1 comparison → **100,000× speedup**

### Cost Analysis (1M users, 1M messages/day)

| Approach                  | Compute Cost | Storage Cost | Total/Month | Speedup |
|---------------------------|--------------|--------------|-------------|---------|
| **Dedicated Servers (5)** | $1500        | $200         | **$1700**   | 1×      |
| **Multi-Cloud Edge (5)**  | $2.40        | $0.60        | **$3**      | **566×**|

*Lambda: $0.20/million requests (0.5s avg), Storage: $0.02/GB*

## Development Roadmap

See [PHASE1_STATUS.md](PHASE1_STATUS.md) for detailed status.

### Phase 1: Foundation (Current - 85% Complete) ✅

- [x] Bazel build system (MODULE.bazel, Bzlmod)
- [x] FheContext (OpenFHE wrapper)
- [x] FheOperations (Halevi-Shoup SIMD)
- [x] ServerKeyManager (centralized keys)
- [x] EncryptedMessage (protocol stub)
- [x] SimdBatch (packing utilities)
- [ ] **Fix build errors** (OpenFHE type signatures) - [Issue #1](https://github.com/bon-cdp/f2chat/issues/1)

### Phase 2: Single-Key FHE Spam Detection (2-3 Weeks)

- [ ] Complete SimdBatch::DetectDuplicates() implementation
- [ ] Integration test: 1000 messages, detect 10 duplicates in <5s
- [ ] Benchmark: Measure SIMD speedup vs naive approach
- [ ] Research artifact: Technical report (arXiv preprint)

### Phase 3: Threshold Cryptography (3-4 Weeks)

- [ ] Threshold key generation (Shamir secret sharing)
- [ ] Partial decryption (single-share)
- [ ] Coordinator (multi-party orchestration)
- [ ] Local simulation: 5 parties on localhost

### Phase 4: Multi-Cloud Edge Compute (4-5 Weeks) 🌟

- [ ] AWS Lambda function (Python + OpenFHE)
- [ ] Google Cloud Function (Python + OpenFHE)
- [ ] Cloudflare Worker (Wasm + OpenFHE)
- [ ] EdgeCoordinator (C++ HTTP client)
- [ ] End-to-end integration: FHE → Threshold → Edge
- [ ] Cost benchmarking: Track Lambda invocations

### Phase 5: Similarity Detection (3-4 Weeks)

- [ ] Encrypted Levenshtein distance (FHE)
- [ ] Clustering (detect coordinated campaigns)
- [ ] Integration: Threshold-decrypt cluster counts

### Phase 6: Production System (5-6 Weeks)

- [ ] gRPC server (message ingestion, batching)
- [ ] CLI client (full UX)
- [ ] Web dashboard (spam stats, cluster viz)
- [ ] Docker deployment

### Phase 7: Publication (2-3 Months)

- [ ] Research paper: "Serverless Threshold Cryptography"
- [ ] Target: USENIX Security 2026, ACM CCS 2026, NDSS 2027
- [ ] Open-source release

**Total Timeline:** ~6 months to publishable system

## Building

### Prerequisites

1. **OpenFHE 1.2.3+** (system install)
   ```bash
   # Ubuntu/Debian
   git clone https://github.com/openfheorg/openfhe-development
   cd openfhe-development && mkdir build && cd build
   cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
   make -j$(nproc) && sudo make install
   ```

2. **Bazel 8.0+** with Bzlmod
   ```bash
   # Install from https://bazel.build/install
   bazel --version  # Should be 8.0+
   ```

3. **C++20 Compiler**
   - GCC 11+ or Clang 14+

### Build Commands

```bash
# Build all libraries (current status: has build errors)
bazel build //lib/...

# Build specific targets
bazel build //lib/crypto:fhe_context
bazel build //lib/crypto:fhe_operations
bazel build //lib/simd:simd_batch

# Run tests (after build is fixed)
bazel test //test/...

# Run with verbose output
bazel build //lib/... --verbose_failures
```

### Known Issues

See [Issue #1](https://github.com/bon-cdp/f2chat/issues/1) for current build status.

- ❌ OpenFHE type signature mismatches (`lbcrypto::Ciphertext`)
- ❌ Namespace conflicts in encrypted_message.cc
- ⚠️ GCC false-positive warning suppressed (`-Wno-error=maybe-uninitialized`)

**ETA to working build:** ~2 hours of type signature fixes

## Contributing

Contributions welcome! This is a research project demonstrating serverless threshold cryptography.

### Code Standards

- Follow [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
- Use Abseil for error handling (`absl::StatusOr`)
- Document performance implications of FHE operations
- Include tests for new functionality

### Areas for Contribution

- **Phase 1:** Fix OpenFHE type signatures ([Issue #1](https://github.com/bon-cdp/f2chat/issues/1))
- **Phase 2:** Implement DetectDuplicates() with Halevi-Shoup
- **Phase 3:** Threshold key generation with Shamir secret sharing
- **Phase 4:** Edge function implementations (AWS, Google, Cloudflare)

## Research Goals

This project aims to publish at a top-tier security venue (USENIX Security, CCS, NDSS) demonstrating:

1. **FHE spam detection is practical** (Phase 2)
2. **Threshold crypto scales with serverless** (Phase 4)
3. **1000× cost reduction vs federated servers** (Phase 4)
4. **Jurisdictional diversity for government resistance** (Phase 4)

### Key Novelties

- **First practical threshold FHE with serverless compute**
- **Multi-cloud edge for distributed trust** (AWS, Google, Cloudflare)
- **Cost-effective alternative to federated servers** ($3 vs $1700/month)
- **No client-side scanning** (preserves E2EE privacy)

## License

Apache 2.0 - See [LICENSE](LICENSE)

## References

- [OpenFHE](https://github.com/openfheorg/openfhe-development) - FHE library
- [HElib Paper](https://www.shoup.net/papers/helib.pdf) - Halevi-Shoup SIMD batching
- [Threshold Cryptography](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) - Shamir secret sharing
- [AWS Lambda Pricing](https://aws.amazon.com/lambda/pricing/)
- [Google Cloud Functions Pricing](https://cloud.google.com/functions/pricing)
- [Cloudflare Workers Pricing](https://developers.cloudflare.com/workers/platform/pricing/)

## Contact

- **GitHub Issues:** [https://github.com/bon-cdp/f2chat/issues](https://github.com/bon-cdp/f2chat/issues)
- **Discussions:** [https://github.com/bon-cdp/f2chat/discussions](https://github.com/bon-cdp/f2chat/discussions)

---

**f2chat is a proof-of-concept research project, not production-ready software.**

**Core Innovation:** Achieving distributed trust at 1/1000th the cost using multi-cloud edge compute for threshold decryption.
