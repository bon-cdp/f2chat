                                                                                                                                                                                    
                                                                                                                                                                                        
 ## Project Overview                                                                                                                                                                    
                                                                                                                                                                                        
 ### The Problem We're Solving                                                                                                                                                          
                                                                                                                                                                                        
 **Current State of Encrypted Messaging:**                                                                                                                                              
 - Signal/WhatsApp: Content is encrypted (E2EE), but **metadata leaks** (server knows Alice→Bob at 3pm)                                                                                 
 - Government surveillance: Focuses on metadata, not content (NSA's PRISM program)                                                                                                      
 - Social graph extraction: Who talks to whom reveals political affiliations, social movements                                                                                          
 - Client-side scanning: Proposed solutions (Apple CSAM) break E2EE privacy                                                                                                             
                                                                                                                                                                                        
 **Traditional E2EE Failure:**                                                                                                                                                          
 ```                                                                                                                                                                                    
 Alice → Server → Bob                                                                                                                                                                   
 Server sees:                                                                                                                                                                           
   ✅ Content: Encrypted (good)                                                                                                                                                          
   ❌ Metadata: Alice sent to Bob at 3pm (leaked!)                                                                                                                                       
   ❌ Identity: Server knows real identities (subpoenable)                                                                                                                               
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 ### Our Solution: FHE Metadata Privacy                                                                                                                                                 
                                                                                                                                                                                        
 **Design:**                                                                                                                                                                            
 ```                                                                                                                                                                                    
 Alice's Device:                                                                                                                                                                        
   Real ID: "Alice" (never leaves device)                                                                                                                                               
   Pseudonym: Pseudo_47291 (unlinkable to "Alice")                                                                                                                                      
   Contact Map: {Bob → Pseudo_88234} (local only)                                                                                                                                       
                                                                                                                                                                                        
 Alice → Server:                                                                                                                                                                        
   FHE_Encrypt(Sender=Pseudo_47291, Receiver=Pseudo_88234, Hash=msg_hash)                                                                                                               
   ThresholdEncrypt(message_content)                                                                                                                                                    
                                                                                                                                                                                        
 Server:                                                                                                                                                                                
   Sees: Encrypted pseudonyms (cannot decrypt)                                                                                                                                          
   Performs: FHE spam detection on encrypted metadata                                                                                                                                   
   Produces: Encrypted spam_count                                                                                                                                                       
                                                                                                                                                                                        
 Edge Functions (AWS + Google + Cloudflare):                                                                                                                                            
   Threshold decrypt: spam_count only (not individual identities)                                                                                                                       
                                                                                                                                                                                        
 Bob's Device:                                                                                                                                                                          
   Maps: Pseudo_47291 → "Alice" (local lookup)                                                                                                                                          
   Displays: "Message from Alice"                                                                                                                                                       
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 **Privacy Guarantees:**                                                                                                                                                                
 1. ✅ Server cannot see real identities (only pseudonyms)                                                                                                                               
 2. ✅ Server cannot decrypt metadata (FHE encrypted)                                                                                                                                    
 3. ✅ Edge functions cannot link pseudonyms to real IDs (device-held mapping)                                                                                                           
 4. ✅ Compromise k-1 edge functions → learn nothing (threshold security)                                                                                                                
 5. ✅ Government subpoena server → no identity mapping available                                                                                                                        
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ## Technical Architecture                                                                                                                                                              
                                                                                                                                                                                        
 ### 1. Identity Model (Device-Held)                                                                                                                                                    
                                                                                                                                                                                        
 **Key Insight:** Only your device knows your real identity.                                                                                                                            
                                                                                                                                                                                        
 ```cpp                                                                                                                                                                                 
 // lib/identity/device_identity.h                                                                                                                                                      
 namespace f2chat {                                                                                                                                                                     
                                                                                                                                                                                        
 class DeviceIdentity {                                                                                                                                                                 
  public:                                                                                                                                                                               
   // Initialize with real identity (phone number, email, username)                                                                                                                     
   static absl::StatusOr<DeviceIdentity> Create(                                                                                                                                        
       const std::string& real_identity,                                                                                                                                                
       const std::string& password);                                                                                                                                                    
                                                                                                                                                                                        
   // Get current pseudonym (rotates periodically for unlinkability)                                                                                                                    
   Pseudonym GetCurrentPseudonym() const;                                                                                                                                               
                                                                                                                                                                                        
   // Rotate pseudonym (daily/weekly) to prevent traffic analysis                                                                                                                       
   absl::Status RotatePseudonym();                                                                                                                                                      
                                                                                                                                                                                        
   // Look up contact's pseudonym (local mapping only)                                                                                                                                  
   absl::StatusOr<Pseudonym> LookupContactPseudonym(                                                                                                                                    
       const std::string& contact_name) const;                                                                                                                                          
                                                                                                                                                                                        
   // Add contact (store their pseudonym locally)                                                                                                                                       
   absl::Status AddContact(                                                                                                                                                             
       const std::string& contact_name,                                                                                                                                                 
       const Pseudonym& their_pseudonym);                                                                                                                                               
                                                                                                                                                                                        
   // Prove pseudonym rotation (cryptographic proof that old_pseudo and new_pseudo                                                                                                      
   // belong to same identity, without revealing real identity)                                                                                                                         
   absl::StatusOr<PseudonymRotationProof> ProvePseudonymRotation(                                                                                                                       
       const Pseudonym& old_pseudonym,                                                                                                                                                  
       const Pseudonym& new_pseudonym) const;                                                                                                                                           
                                                                                                                                                                                        
  private:                                                                                                                                                                              
   std::string real_identity_;           // Never sent to server                                                                                                                        
   PrivateKey identity_secret_key_;      // For signing/proving                                                                                                                         
   Pseudonym current_pseudonym_;         // Current unlinkable ID                                                                                                                       
   absl::Time pseudonym_created_at_;     // For rotation tracking                                                                                                                       
                                                                                                                                                                                        
   // Contact mapping (local storage only)                                                                                                                                              
   absl::flat_hash_map<std::string, Pseudonym> contacts_;                                                                                                                               
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 // Pseudonym: Unlinkable identifier (UUID-like)                                                                                                                                        
 class Pseudonym {                                                                                                                                                                      
  public:                                                                                                                                                                               
   static Pseudonym Generate();  // Cryptographically random                                                                                                                            
                                                                                                                                                                                        
   // Convert to integer for FHE operations                                                                                                                                             
   uint64_t ToInt() const;                                                                                                                                                              
                                                                                                                                                                                        
   std::string ToString() const;  // For storage/display                                                                                                                                
                                                                                                                                                                                        
  private:                                                                                                                                                                              
   std::array<uint8_t, 32> bytes_;  // 256-bit random ID                                                                                                                                
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 }  // namespace f2chat                                                                                                                                                                 
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 **Storage:** Device-local only (SQLite, encrypted with device password).                                                                                                               
                                                                                                                                                                                        
 **Security Model:**                                                                                                                                                                    
 - Lose device → Cannot link past messages to you (forward secrecy)                                                                                                                     
 - Subpoena server → No identity mapping exists                                                                                                                                         
 - Compromise device → Only affects that user (not entire network)                                                                                                                      
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### 2. FHE Metadata Encryption                                                                                                                                                         
                                                                                                                                                                                        
 **What We Encrypt with FHE:**                                                                                                                                                          
 - Sender pseudonym (who sent)                                                                                                                                                          
 - Receiver pseudonym (who received)                                                                                                                                                    
 - Message hash (for spam detection)                                                                                                                                                    
 - Timestamp (encrypted, for ordering)                                                                                                                                                  
                                                                                                                                                                                        
 **Why FHE (not just threshold crypto):**                                                                                                                                               
 - FHE allows server to perform spam detection **without decrypting metadata**                                                                                                          
 - Server can detect: "A pseudonym sent 500 identical messages" (encrypted!)                                                                                                            
 - Threshold decryption reveals only spam count, not individual identities                                                                                                              
                                                                                                                                                                                        
 ```cpp                                                                                                                                                                                 
 // lib/message/encrypted_metadata.h                                                                                                                                                    
 namespace f2chat {                                                                                                                                                                     
                                                                                                                                                                                        
 struct EncryptedMetadata {                                                                                                                                                             
   // All fields FHE-encrypted                                                                                                                                                          
   lbcrypto::Ciphertext sender_pseudonym;     // FHE_Enc(Pseudonym_A)                                                                                                                   
   lbcrypto::Ciphertext receiver_pseudonym;   // FHE_Enc(Pseudonym_B)                                                                                                                   
   lbcrypto::Ciphertext message_hash;         // FHE_Enc(Hash(content))                                                                                                                 
   lbcrypto::Ciphertext timestamp;            // FHE_Enc(unix_timestamp)                                                                                                                
                                                                                                                                                                                        
   // Signature (proves sender owns pseudonym, not FHE encrypted)                                                                                                                       
   Signature pseudonym_signature;                                                                                                                                                       
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 class MetadataEncryptor {                                                                                                                                                              
  public:                                                                                                                                                                               
   // Encrypt metadata with FHE public key                                                                                                                                              
   static absl::StatusOr<EncryptedMetadata> Encrypt(                                                                                                                                    
       const Pseudonym& sender,                                                                                                                                                         
       const Pseudonym& receiver,                                                                                                                                                       
       const std::vector<uint8_t>& message_hash,                                                                                                                                        
       absl::Time timestamp,                                                                                                                                                            
       const lbcrypto::PublicKey& fhe_public_key);                                                                                                                                      
                                                                                                                                                                                        
   // Decrypt metadata (only for threshold parties)                                                                                                                                     
   static absl::StatusOr<PlaintextMetadata> Decrypt(                                                                                                                                    
       const EncryptedMetadata& encrypted,                                                                                                                                              
       const lbcrypto::PrivateKey& fhe_secret_key);                                                                                                                                     
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 }  // namespace f2chat                                                                                                                                                                 
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 **FHE Scheme:** BGV (supports integer operations, needed for equality checks).                                                                                                         
                                                                                                                                                                                        
 **Parameters:**                                                                                                                                                                        
 - Security: 128-bit                                                                                                                                                                    
 - Ring dimension: 8192 (supports SIMD batching)                                                                                                                                        
 - Plaintext modulus: 65537 (for integer metadata)                                                                                                                                      
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### 3. Spam Detection on Encrypted Metadata                                                                                                                                            
                                                                                                                                                                                        
 **Algorithm:** Halevi-Shoup SIMD Binary Reduction (O(log N) rotations).                                                                                                                
                                                                                                                                                                                        
 **Goal:** Detect duplicate message hashes across 1000s of encrypted metadata records.                                                                                                  
                                                                                                                                                                                        
 ```cpp                                                                                                                                                                                 
 // lib/crypto/fhe_spam_detection.h                                                                                                                                                     
 namespace f2chat {                                                                                                                                                                     
                                                                                                                                                                                        
 class FheSpamDetector {                                                                                                                                                                
  public:                                                                                                                                                                               
   // Detect duplicates in batch of encrypted metadata                                                                                                                                  
   // Returns: Encrypted spam count (still FHE encrypted!)                                                                                                                              
   absl::StatusOr<lbcrypto::Ciphertext> DetectDuplicates(                                                                                                                               
       const std::vector<EncryptedMetadata>& batch,                                                                                                                                     
       const lbcrypto::CryptoContext& crypto_context);                                                                                                                                  
                                                                                                                                                                                        
   // Implementation: Halevi-Shoup binary reduction                                                                                                                                     
   // 1. Pack metadata into SIMD slots (8192 slots per ciphertext)                                                                                                                      
   // 2. For each unique hash:                                                                                                                                                          
   //    - Compare all slots to target hash (encrypted equality)                                                                                                                        
   //    - Sum matches across slots (binary reduction, O(log N))                                                                                                                        
   // 3. Output: Encrypted count of duplicates                                                                                                                                          
                                                                                                                                                                                        
  private:                                                                                                                                                                              
   // Encrypted equality check: (a - b)^(p-1) mod p = 1 if equal, 0 if not                                                                                                              
   lbcrypto::Ciphertext EvalEqual(                                                                                                                                                      
       const lbcrypto::Ciphertext& ct1,                                                                                                                                                 
       const lbcrypto::Ciphertext& ct2,                                                                                                                                                 
       const lbcrypto::CryptoContext& crypto_context) const;                                                                                                                            
                                                                                                                                                                                        
   // Sum across all SIMD slots (Halevi-Shoup binary reduction)                                                                                                                         
   lbcrypto::Ciphertext SumAllSlots(                                                                                                                                                    
       const lbcrypto::Ciphertext& ct,                                                                                                                                                  
       const lbcrypto::CryptoContext& crypto_context) const;                                                                                                                            
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 }  // namespace f2chat                                                                                                                                                                 
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 **Performance Target:**                                                                                                                                                                
 - Batch size: 1000 metadata records                                                                                                                                                    
 - SIMD packing: 8192 slots (8× batches per ciphertext)                                                                                                                                 
 - Spam detection latency: <5 seconds                                                                                                                                                   
 - Speedup vs naive: 100,000× (SIMD batching)                                                                                                                                           
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### 4. Threshold Decryption (Serverless Edge)                                                                                                                                          
                                                                                                                                                                                        
 **Threat Model:** Server is semi-trusted (honest-but-curious).                                                                                                                         
 - Server follows protocol but tries to learn identities                                                                                                                                
 - Server does FHE operations but **cannot decrypt metadata**                                                                                                                           
 - Only k=3 of 5 edge functions can decrypt spam result                                                                                                                                 
                                                                                                                                                                                        
 **Threshold Setup:**                                                                                                                                                                   
 1. Generate FHE keypair: (PK_global, SK_global)                                                                                                                                        
 2. Split SK_global into 5 shares: [Share_1, Share_2, Share_3, Share_4, Share_5]                                                                                                        
 3. Deploy shares:                                                                                                                                                                      
    - Share_1 → AWS Lambda (US East)                                                                                                                                                    
    - Share_2 → Google Cloud Function (EU West)                                                                                                                                         
    - Share_3 → Cloudflare Worker (Global CDN)                                                                                                                                          
    - Share_4 → Azure Function (Asia)                                                                                                                                                   
    - Share_5 → Vercel Edge (Backup)                                                                                                                                                    
 4. Threshold: k=3 (any 3 can decrypt)                                                                                                                                                  
                                                                                                                                                                                        
 ```cpp                                                                                                                                                                                 
 // lib/threshold/threshold_keygen.h                                                                                                                                                    
 namespace f2chat {                                                                                                                                                                     
                                                                                                                                                                                        
 struct ThresholdKeyShare {                                                                                                                                                             
   int share_id;                  // 1-5                                                                                                                                                
   std::vector<uint8_t> share;    // Secret share (Shamir)                                                                                                                              
   lbcrypto::PublicKey public_key; // Same for all shares                                                                                                                               
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 class ThresholdKeyGenerator {                                                                                                                                                          
  public:                                                                                                                                                                               
   // Generate threshold key shares (k-of-n)                                                                                                                                            
   static absl::StatusOr<std::vector<ThresholdKeyShare>> GenerateShares(                                                                                                                
       int k,  // Threshold (e.g., 3)                                                                                                                                                   
       int n,  // Total shares (e.g., 5)                                                                                                                                                
       const lbcrypto::CryptoContext& crypto_context);                                                                                                                                  
                                                                                                                                                                                        
   // Combine partial decryptions from k shares                                                                                                                                         
   static absl::StatusOr<PlaintextResult> CombinePartialDecryptions(                                                                                                                    
       const std::vector<PartialDecryption>& partials,                                                                                                                                  
       int k);                                                                                                                                                                          
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 // lib/threshold/partial_decrypt.h                                                                                                                                                     
 class PartialDecryptor {                                                                                                                                                               
  public:                                                                                                                                                                               
   // Partial decrypt with single share (runs on edge function)                                                                                                                         
   static absl::StatusOr<PartialDecryption> Decrypt(                                                                                                                                    
       const lbcrypto::Ciphertext& ciphertext,                                                                                                                                          
       const ThresholdKeyShare& share);                                                                                                                                                 
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 }  // namespace f2chat                                                                                                                                                                 
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 **Edge Function (AWS Lambda Example):**                                                                                                                                                
 ```python                                                                                                                                                                              
 # edge_functions/aws_lambda/lambda_function.py                                                                                                                                         
 import boto3                                                                                                                                                                           
 import json                                                                                                                                                                            
 import openfhe  # Assume Python bindings                                                                                                                                               
                                                                                                                                                                                        
 secrets = boto3.client('secretsmanager')                                                                                                                                               
                                                                                                                                                                                        
 def lambda_handler(event, context):                                                                                                                                                    
     # Fetch threshold share from AWS Secrets Manager                                                                                                                                   
     share_1 = secrets.get_secret_value(SecretId='f2chat-threshold-share-1')                                                                                                            
                                                                                                                                                                                        
     # Deserialize ciphertext from request                                                                                                                                              
     ciphertext_bytes = event['ciphertext']                                                                                                                                             
     ciphertext = openfhe.Deserialize(ciphertext_bytes)                                                                                                                                 
                                                                                                                                                                                        
     # Partial decrypt with Share 1                                                                                                                                                     
     partial = openfhe.PartialDecrypt(ciphertext, share_1)                                                                                                                              
                                                                                                                                                                                        
     return {                                                                                                                                                                           
         'statusCode': 200,                                                                                                                                                             
         'body': json.dumps({                                                                                                                                                           
             'share_id': 1,                                                                                                                                                             
             'partial_decryption': openfhe.Serialize(partial)                                                                                                                           
         })                                                                                                                                                                             
     }                                                                                                                                                                                  
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 **Coordinator (C++ client):**                                                                                                                                                          
 ```cpp                                                                                                                                                                                 
 // lib/edge/edge_coordinator.h                                                                                                                                                         
 namespace f2chat {                                                                                                                                                                     
                                                                                                                                                                                        
 class EdgeCoordinator {                                                                                                                                                                
  public:                                                                                                                                                                               
   // Invoke edge functions in parallel, combine results                                                                                                                                
   absl::StatusOr<int64_t> ThresholdDecryptSpamCount(                                                                                                                                   
       const lbcrypto::Ciphertext& encrypted_count);                                                                                                                                    
                                                                                                                                                                                        
  private:                                                                                                                                                                              
   // HTTP client for edge functions                                                                                                                                                    
   absl::StatusOr<PartialDecryption> InvokeLambda(                                                                                                                                      
       const std::string& url,                                                                                                                                                          
       const lbcrypto::Ciphertext& ciphertext);                                                                                                                                         
                                                                                                                                                                                        
   // Invoke k edge functions in parallel                                                                                                                                               
   absl::StatusOr<std::vector<PartialDecryption>> InvokeParallel(                                                                                                                       
       const lbcrypto::Ciphertext& ciphertext,                                                                                                                                          
       int k);                                                                                                                                                                          
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 }  // namespace f2chat                                                                                                                                                                 
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### 5. Message Content Encryption (Threshold Crypto)                                                                                                                                   
                                                                                                                                                                                        
 **Separate from FHE:** Message content uses **threshold ElGamal** (not FHE).                                                                                                           
                                                                                                                                                                                        
 **Why not FHE for content?**                                                                                                                                                           
 - FHE is expensive (slow, large ciphertexts)                                                                                                                                           
 - We only need FHE for **metadata** (so server can compute on it)                                                                                                                      
 - Content doesn't need computation (just encrypt/decrypt)                                                                                                                              
                                                                                                                                                                                        
 ```cpp                                                                                                                                                                                 
 // lib/crypto/threshold_elgamal.h                                                                                                                                                      
 namespace f2chat {                                                                                                                                                                     
                                                                                                                                                                                        
 class ThresholdElGamal {                                                                                                                                                               
  public:                                                                                                                                                                               
   // Encrypt message with threshold public key                                                                                                                                         
   static absl::StatusOr<Ciphertext> Encrypt(                                                                                                                                           
       const std::string& plaintext,                                                                                                                                                    
       const PublicKey& threshold_public_key);                                                                                                                                          
                                                                                                                                                                                        
   // Partial decrypt with single share                                                                                                                                                 
   static absl::StatusOr<PartialDecryption> PartialDecrypt(                                                                                                                             
       const Ciphertext& ciphertext,                                                                                                                                                    
       const ThresholdKeyShare& share);                                                                                                                                                 
                                                                                                                                                                                        
   // Combine k partial decryptions → plaintext                                                                                                                                         
   static absl::StatusOr<std::string> CombineDecryptions(                                                                                                                               
       const std::vector<PartialDecryption>& partials,                                                                                                                                  
       int k);                                                                                                                                                                          
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 }  // namespace f2chat                                                                                                                                                                 
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 **Security:** k-of-n threshold (same as FHE metadata decryption).                                                                                                                      
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ## Implementation Phases                                                                                                                                                               
                                                                                                                                                                                        
 ### Phase 1: Foundation (1 Week)                                                                                                                                                       
                                                                                                                                                                                        
 **Goal:** Build system setup, FHE basics, identity model.                                                                                                                              
                                                                                                                                                                                        
 **Deliverables:**                                                                                                                                                                      
 1. Bazel build system (MODULE.bazel, Bzlmod)                                                                                                                                           
    - OpenFHE 1.2.3+ integration                                                                                                                                                        
    - Abseil for error handling (StatusOr)                                                                                                                                              
    - GoogleTest for unit tests                                                                                                                                                         
                                                                                                                                                                                        
 2. Device Identity (`lib/identity/device_identity.{h,cc}`)                                                                                                                             
    - Pseudonym generation                                                                                                                                                              
    - Local contact mapping                                                                                                                                                             
    - Pseudonym rotation                                                                                                                                                                
    - Unit tests                                                                                                                                                                        
                                                                                                                                                                                        
 3. FHE Context (`lib/crypto/fhe_context.{h,cc}`)                                                                                                                                       
    - OpenFHE wrapper (BGV, 8192 slots, 128-bit security)                                                                                                                               
    - Key generation                                                                                                                                                                    
    - Encrypt/decrypt integers (for pseudonyms)                                                                                                                                         
    - Unit tests                                                                                                                                                                        
                                                                                                                                                                                        
 4. Encrypted Metadata (`lib/message/encrypted_metadata.{h,cc}`)                                                                                                                        
    - MetadataEncryptor class                                                                                                                                                           
    - FHE encrypt sender/receiver/hash/timestamp                                                                                                                                        
    - Serialization (Protobuf or Cap'n Proto)                                                                                                                                           
    - Unit tests                                                                                                                                                                        
                                                                                                                                                                                        
 **Success Criteria:**                                                                                                                                                                  
 - ✅ `bazel build //lib/...` succeeds with `-Werror`                                                                                                                                    
 - ✅ `bazel test //test/...` all tests pass                                                                                                                                             
 - ✅ Can generate pseudonyms, encrypt metadata, serialize                                                                                                                               
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### Phase 2: FHE Spam Detection (2-3 Weeks)                                                                                                                                            
                                                                                                                                                                                        
 **Goal:** Halevi-Shoup SIMD spam detection on encrypted metadata.                                                                                                                      
                                                                                                                                                                                        
 **Deliverables:**                                                                                                                                                                      
 1. FHE Operations (`lib/crypto/fhe_operations.{h,cc}`)                                                                                                                                 
    - EvalEqual (encrypted equality check)                                                                                                                                              
    - SumAllSlots (Halevi-Shoup binary reduction)                                                                                                                                       
    - BroadcastToAllSlots (slot replication)                                                                                                                                            
    - SIMD packing/unpacking utilities                                                                                                                                                  
                                                                                                                                                                                        
 2. Spam Detector (`lib/crypto/fhe_spam_detection.{h,cc}`)                                                                                                                              
    - DetectDuplicates (batch of encrypted metadata → encrypted spam count)                                                                                                             
    - Integration with FheOperations                                                                                                                                                    
    - Performance benchmarks                                                                                                                                                            
                                                                                                                                                                                        
 3. Integration Test                                                                                                                                                                    
    - Batch 1000 encrypted metadata records                                                                                                                                             
    - Detect 10 duplicates in <5 seconds                                                                                                                                                
    - Verify SIMD speedup (≥100× vs naive)                                                                                                                                              
                                                                                                                                                                                        
 **Success Criteria:**                                                                                                                                                                  
 - ✅ Detect duplicates in 1000-record batch in <5s                                                                                                                                      
 - ✅ SIMD speedup: ≥100× vs naive O(N²)                                                                                                                                                 
 - ✅ Comprehensive unit tests (edge cases, empty batches)                                                                                                                               
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### Phase 3: Threshold Cryptography (3-4 Weeks)                                                                                                                                        
                                                                                                                                                                                        
 **Goal:** Split decryption across multiple parties.                                                                                                                                    
                                                                                                                                                                                        
 **Deliverables:**                                                                                                                                                                      
 1. Threshold Key Generation (`lib/threshold/threshold_keygen.{h,cc}`)                                                                                                                  
    - Shamir secret sharing (k-of-n)                                                                                                                                                    
    - Generate 5 shares from SK_global                                                                                                                                                  
    - Verify threshold property (k=3 required)                                                                                                                                          
                                                                                                                                                                                        
 2. Partial Decryption (`lib/threshold/partial_decrypt.{h,cc}`)                                                                                                                         
    - Single-share partial decrypt                                                                                                                                                      
    - Combine k partial decryptions → plaintext                                                                                                                                         
    - Unit tests (verify k-1 shares fail)                                                                                                                                               
                                                                                                                                                                                        
 3. Local Simulation                                                                                                                                                                    
    - Simulate 5 parties on localhost (different ports)                                                                                                                                 
    - Full threshold decryption of spam count                                                                                                                                           
    - Measure latency overhead (threshold vs single-key)                                                                                                                                
                                                                                                                                                                                        
 **Success Criteria:**                                                                                                                                                                  
 - ✅ Threshold requires exactly k=3 shares (not k-1, not k+1)                                                                                                                           
 - ✅ Simulate 5 parties locally, any 3 can decrypt                                                                                                                                      
 - ✅ Latency overhead: <2× vs single-key decryption                                                                                                                                     
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### Phase 4: Serverless Edge Deployment (4-5 Weeks)                                                                                                                                    
                                                                                                                                                                                        
 **Goal:** Deploy threshold shares to AWS, Google, Cloudflare.                                                                                                                          
                                                                                                                                                                                        
 **Deliverables:**                                                                                                                                                                      
 1. Edge Functions                                                                                                                                                                      
    - `edge_functions/aws_lambda/lambda_function.py` (AWS Lambda)                                                                                                                       
    - `edge_functions/google_cloud/main.py` (Google Cloud Function)                                                                                                                     
    - `edge_functions/cloudflare_workers/worker.js` (Cloudflare Worker)                                                                                                                 
    - Each function: Fetch share from secrets manager, partial decrypt, return result                                                                                                   
                                                                                                                                                                                        
 2. Edge Coordinator (`lib/edge/edge_coordinator.{h,cc}`)                                                                                                                               
    - HTTP client (libcurl or gRPC)                                                                                                                                                     
    - Parallel invocation of k edge functions                                                                                                                                           
    - Timeout handling (if one provider fails)                                                                                                                                          
    - Combine partial decryptions                                                                                                                                                       
                                                                                                                                                                                        
 3. Deployment Automation                                                                                                                                                               
    - `scripts/deploy_threshold_shares.sh` (deploy to all 3 clouds)                                                                                                                     
    - Terraform/Pulumi configuration                                                                                                                                                    
    - Secret distribution (AWS Secrets Manager, Google Secret Manager, Cloudflare KV)                                                                                                   
                                                                                                                                                                                        
 4. End-to-End Integration                                                                                                                                                              
    - Client → Encrypt metadata → Server → FHE spam detection → Edge threshold → Result                                                                                                 
    - Measure cold start vs warm latency                                                                                                                                                
    - Cost tracking (Lambda invocations, CloudWatch logs)                                                                                                                               
                                                                                                                                                                                        
 **Success Criteria:**                                                                                                                                                                  
 - ✅ Deploy to 3+ cloud providers (AWS, Google, Cloudflare)                                                                                                                             
 - ✅ Threshold decryption with real edge functions (not simulation)                                                                                                                     
 - ✅ Cold start latency: <1 second                                                                                                                                                      
 - ✅ Warm latency: <150ms (2× single-key baseline)                                                                                                                                      
 - ✅ Cost: <$3/month for 1M users                                                                                                                                                       
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### Phase 5: Private Information Retrieval (3-4 Weeks)                                                                                                                                 
                                                                                                                                                                                        
 **Goal:** Fetch messages without revealing which mailbox you're querying.                                                                                                              
                                                                                                                                                                                        
 **Deliverables:**                                                                                                                                                                      
 1. PIR Implementation (`lib/pir/pir_client.{h,cc}`)                                                                                                                                    
    - Oblivious RAM (ORAM) or download-all approach                                                                                                                                     
    - Generate PIR query (encrypted mailbox index)                                                                                                                                      
    - Decrypt PIR response                                                                                                                                                              
                                                                                                                                                                                        
 2. Server PIR Endpoint (`server/pir_server.{h,cc}`)                                                                                                                                    
    - Process PIR query without learning which mailbox                                                                                                                                  
    - Return messages (client filters locally)                                                                                                                                          
                                                                                                                                                                                        
 3. Benchmark                                                                                                                                                                           
    - Measure PIR overhead vs naive (reveal mailbox)                                                                                                                                    
    - Bandwidth cost (download-all vs ORAM)                                                                                                                                             
    - Latency (query generation + response decryption)                                                                                                                                  
                                                                                                                                                                                        
 **Success Criteria:**                                                                                                                                                                  
 - ✅ Fetch messages without server learning mailbox ID                                                                                                                                  
 - ✅ Bandwidth overhead: <10× vs naive (acceptable for privacy)                                                                                                                         
 - ✅ Latency: <5 seconds for 1000-message mailbox                                                                                                                                       
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### Phase 6: Production System (5-6 Weeks)                                                                                                                                             
                                                                                                                                                                                        
 **Goal:** Deployable messaging system.                                                                                                                                                 
                                                                                                                                                                                        
 **Deliverables:**                                                                                                                                                                      
 1. gRPC Server (`server/f2chat_server.{h,cc}`)                                                                                                                                         
    - Message ingestion (encrypted metadata + threshold content)                                                                                                                        
    - Periodic batching (every 5 minutes)                                                                                                                                               
    - Spam detection (FHE)                                                                                                                                                              
    - Threshold decryption coordination                                                                                                                                                 
    - PostgreSQL storage (encrypted metadata, messages)                                                                                                                                 
                                                                                                                                                                                        
 2. CLI Client (`client/f2chat_cli.cc`)                                                                                                                                                 
    - Send message (encrypt metadata + content)                                                                                                                                         
    - Receive messages (PIR query)                                                                                                                                                      
    - View spam alerts                                                                                                                                                                  
    - Manage contacts (add, remove, rotate pseudonyms)                                                                                                                                  
                                                                                                                                                                                        
 3. Docker Deployment                                                                                                                                                                   
    - Dockerfile for server                                                                                                                                                             
    - Docker Compose (server + Postgres + Redis)                                                                                                                                        
    - Kubernetes manifests                                                                                                                                                              
                                                                                                                                                                                        
 **Success Criteria:**                                                                                                                                                                  
 - ✅ Deployable with `docker compose up`                                                                                                                                                
 - ✅ Handle 100,000 messages/hour                                                                                                                                                       
 - ✅ User-friendly CLI (clear spam warnings)                                                                                                                                            
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### Phase 7: Research Paper (2-3 Months)                                                                                                                                               
                                                                                                                                                                                        
 **Goal:** Publish at USENIX Security 2026, CCS 2026, or NDSS 2027.                                                                                                                     
                                                                                                                                                                                        
 **Paper Title:**                                                                                                                                                                       
 "FHE Metadata Privacy: Defeating Surveillance with Serverless Threshold Cryptography"                                                                                                  
                                                                                                                                                                                        
 **Paper Structure (12-15 pages):**                                                                                                                                                     
                                                                                                                                                                                        
 1. **Introduction (2 pages)**                                                                                                                                                          
    - Problem: E2EE leaks metadata (NSA PRISM, government surveillance)                                                                                                                 
    - Limitations: Signal sealed sender (partial solution)                                                                                                                              
    - Threat: Metadata collection for social graph extraction                                                                                                                           
    - Our approach: FHE metadata + serverless threshold                                                                                                                                 
                                                                                                                                                                                        
 2. **Background (2 pages)**                                                                                                                                                            
    - FHE basics (BGV scheme)                                                                                                                                                           
    - SIMD batching (Halevi-Shoup)                                                                                                                                                      
    - Threshold cryptography (Shamir secret sharing)                                                                                                                                    
    - Serverless computing (Lambda, Cloud Functions, Workers)                                                                                                                           
                                                                                                                                                                                        
 3. **System Design (3 pages)**                                                                                                                                                         
    - Device-held identity model                                                                                                                                                        
    - FHE metadata encryption                                                                                                                                                           
    - Spam detection on encrypted metadata                                                                                                                                              
    - Threshold decryption architecture                                                                                                                                                 
    - PIR for message retrieval                                                                                                                                                         
                                                                                                                                                                                        
 4. **Implementation (2 pages)**                                                                                                                                                        
    - OpenFHE integration                                                                                                                                                               
    - SIMD optimization (Halevi-Shoup binary reduction)                                                                                                                                 
    - Edge function deployment (AWS, Google, Cloudflare)                                                                                                                                
    - Coordinator protocol                                                                                                                                                              
                                                                                                                                                                                        
 5. **Evaluation (3 pages)**                                                                                                                                                            
    - Performance:                                                                                                                                                                      
      - Metadata encryption latency (client)                                                                                                                                            
      - Spam detection throughput (server)                                                                                                                                              
      - Threshold decryption latency (edge cold vs warm)                                                                                                                                
    - Scalability:                                                                                                                                                                      
      - 1K, 10K, 100K, 1M users                                                                                                                                                         
    - Cost:                                                                                                                                                                             
      - Dedicated servers: $1700/month                                                                                                                                                  
      - Multi-cloud edge: $3/month                                                                                                                                                      
      - **1000× reduction**                                                                                                                                                             
    - Security:                                                                                                                                                                         
      - Resistance to server compromise                                                                                                                                                 
      - Resistance to government coercion (jurisdictional diversity)                                                                                                                    
                                                                                                                                                                                        
 6. **Related Work (1 page)**                                                                                                                                                           
    - Signal sealed sender                                                                                                                                                              
    - PIR for messaging (Pung, Stadium)                                                                                                                                                 
    - FHE messaging (academic proposals)                                                                                                                                                
    - Threshold messaging (Keybase, federated servers)                                                                                                                                  
    - **Novelty:** FHE metadata + serverless threshold                                                                                                                                  
                                                                                                                                                                                        
 7. **Limitations & Future Work (1 page)**                                                                                                                                              
    - Metadata still leaked during pseudonym rotation                                                                                                                                   
    - PIR bandwidth overhead                                                                                                                                                            
    - Multi-key FHE (future: each user has own key)                                                                                                                                     
                                                                                                                                                                                        
 8. **Conclusion (0.5 page)**                                                                                                                                                           
    - Demonstrated: FHE metadata privacy at scale                                                                                                                                       
    - Demonstrated: Serverless threshold is practical                                                                                                                                   
    - Impact: Defeat metadata surveillance without federated servers                                                                                                                    
                                                                                                                                                                                        
 **Target Venues:**                                                                                                                                                                     
 - **USENIX Security 2026** (systems focus, practical deployments)                                                                                                                      
 - **ACM CCS 2026** (crypto + systems)                                                                                                                                                  
 - **NDSS 2027** (network security, privacy)                                                                                                                                            
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ## Code Quality Standards                                                                                                                                                              
                                                                                                                                                                                        
 ### 1. C++ Style Guide                                                                                                                                                                 
                                                                                                                                                                                        
 **Follow Google C++ Style Guide:**                                                                                                                                                     
 - https://google.github.io/styleguide/cppguide.html                                                                                                                                    
 - Exception: Allow exceptions (required by OpenFHE)                                                                                                                                    
                                                                                                                                                                                        
 **Key Rules:**                                                                                                                                                                         
 - Use `absl::StatusOr` for error handling                                                                                                                                              
 - Prefer `std::unique_ptr` over raw pointers                                                                                                                                           
 - Document performance implications in comments                                                                                                                                        
 - Use `const` liberally                                                                                                                                                                
 - RAII for resource management                                                                                                                                                         
                                                                                                                                                                                        
 **Example:**                                                                                                                                                                           
 ```cpp                                                                                                                                                                                 
 // lib/crypto/fhe_context.h                                                                                                                                                            
 namespace f2chat {                                                                                                                                                                     
                                                                                                                                                                                        
 // FHE context for metadata encryption (BGV scheme, 8192 slots).                                                                                                                       
 //                                                                                                                                                                                     
 // Thread Safety: This class is thread-safe. Multiple threads can safely                                                                                                               
 // call Encrypt/Decrypt concurrently.                                                                                                                                                  
 //                                                                                                                                                                                     
 // Performance: Encryption is ~50-100ms, decryption is ~50-100ms.                                                                                                                      
 // Use SIMD batching for throughput (8192 metadata per operation).                                                                                                                     
 class FheContext {                                                                                                                                                                     
  public:                                                                                                                                                                               
   // Creates FHE context with default parameters (BGV, 8192 slots, 128-bit).                                                                                                           
   //                                                                                                                                                                                   
   // Returns:                                                                                                                                                                          
   //   FheContext instance                                                                                                                                                             
   //   Error status if OpenFHE initialization fails                                                                                                                                    
   static absl::StatusOr<FheContext> Create();                                                                                                                                          
                                                                                                                                                                                        
   // Encrypts an integer (for pseudonym IDs).                                                                                                                                          
   //                                                                                                                                                                                   
   // Args:                                                                                                                                                                             
   //   plaintext: Integer to encrypt (64-bit)                                                                                                                                          
   //   public_key: FHE public key                                                                                                                                                      
   //                                                                                                                                                                                   
   // Returns:                                                                                                                                                                          
   //   FHE ciphertext                                                                                                                                                                  
   //   Error status if encryption fails                                                                                                                                                
   //                                                                                                                                                                                   
   // Performance: ~50-100ms (single operation)                                                                                                                                         
   absl::StatusOr<lbcrypto::Ciphertext> Encrypt(                                                                                                                                        
       int64_t plaintext,                                                                                                                                                               
       const lbcrypto::PublicKey& public_key) const;                                                                                                                                    
                                                                                                                                                                                        
   // (Additional methods...)                                                                                                                                                           
                                                                                                                                                                                        
  private:                                                                                                                                                                              
   lbcrypto::CryptoContext crypto_context_;                                                                                                                                             
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 }  // namespace f2chat                                                                                                                                                                 
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### 2. Build System (Bazel + Bzlmod)                                                                                                                                                   
                                                                                                                                                                                        
 **Use Bazel 8.0+ with MODULE.bazel (Bzlmod):**                                                                                                                                         
 ```python                                                                                                                                                                              
 # MODULE.bazel                                                                                                                                                                         
 module(name = "f2chat", version = "1.0.0")                                                                                                                                             
                                                                                                                                                                                        
 # Dependencies                                                                                                                                                                         
 bazel_dep(name = "abseil-cpp", version = "20240116.0", repo_name = "com_google_absl")                                                                                                  
 bazel_dep(name = "googletest", version = "1.15.2")                                                                                                                                     
 bazel_dep(name = "protobuf", version = "27.0")                                                                                                                                         
                                                                                                                                                                                        
 # OpenFHE (system install at /usr/local)                                                                                                                                               
 # See third_party/openfhe/BUILD.bazel                                                                                                                                                  
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 **Bazel Configuration:**                                                                                                                                                               
 ```python                                                                                                                                                                              
 # .bazelrc                                                                                                                                                                             
 # C++20 with strict warnings                                                                                                                                                           
 build --cxxopt=-std=c++20                                                                                                                                                              
 build --cxxopt=-Wall                                                                                                                                                                   
 build --cxxopt=-Wextra                                                                                                                                                                 
 build --cxxopt=-Werror                                                                                                                                                                 
                                                                                                                                                                                        
 # Exceptions enabled (required by OpenFHE)                                                                                                                                             
 # Deviates from Google C++ Style Guide, but necessary                                                                                                                                  
                                                                                                                                                                                        
 # Optimization                                                                                                                                                                         
 build --cxxopt=-O2                                                                                                                                                                     
 build --cxxopt=-g                                                                                                                                                                      
                                                                                                                                                                                        
 # Test output                                                                                                                                                                          
 test --test_output=errors                                                                                                                                                              
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### 3. Testing Standards                                                                                                                                                               
                                                                                                                                                                                        
 **Use GoogleTest for all tests:**                                                                                                                                                      
 ```cpp                                                                                                                                                                                 
 // test/identity/device_identity_test.cc                                                                                                                                               
 #include "lib/identity/device_identity.h"                                                                                                                                              
 #include <gtest/gtest.h>                                                                                                                                                               
                                                                                                                                                                                        
 namespace f2chat {                                                                                                                                                                     
 namespace {                                                                                                                                                                            
                                                                                                                                                                                        
 TEST(DeviceIdentityTest, CreateAndGetPseudonym) {                                                                                                                                      
   auto identity_or = DeviceIdentity::Create("alice@example.com", "password");                                                                                                          
   ASSERT_TRUE(identity_or.ok());                                                                                                                                                       
                                                                                                                                                                                        
   auto identity = std::move(identity_or).value();                                                                                                                                      
   Pseudonym pseudo = identity.GetCurrentPseudonym();                                                                                                                                   
                                                                                                                                                                                        
   EXPECT_NE(pseudo.ToString(), "alice@example.com");                                                                                                                                   
   EXPECT_EQ(pseudo.ToString().size(), 64);  // 256-bit hex                                                                                                                             
 }                                                                                                                                                                                      
                                                                                                                                                                                        
 TEST(DeviceIdentityTest, PseudonymRotation) {                                                                                                                                          
   auto identity = DeviceIdentity::Create("alice", "pw").value();                                                                                                                       
                                                                                                                                                                                        
   Pseudonym old_pseudo = identity.GetCurrentPseudonym();                                                                                                                               
   ASSERT_TRUE(identity.RotatePseudonym().ok());                                                                                                                                        
   Pseudonym new_pseudo = identity.GetCurrentPseudonym();                                                                                                                               
                                                                                                                                                                                        
   EXPECT_NE(old_pseudo.ToString(), new_pseudo.ToString());                                                                                                                             
 }                                                                                                                                                                                      
                                                                                                                                                                                        
 TEST(DeviceIdentityTest, ContactMapping) {                                                                                                                                             
   auto alice = DeviceIdentity::Create("alice", "pw").value();                                                                                                                          
   Pseudonym bob_pseudo = Pseudonym::Generate();                                                                                                                                        
                                                                                                                                                                                        
   ASSERT_TRUE(alice.AddContact("Bob", bob_pseudo).ok());                                                                                                                               
                                                                                                                                                                                        
   auto lookup = alice.LookupContactPseudonym("Bob");                                                                                                                                   
   ASSERT_TRUE(lookup.ok());                                                                                                                                                            
   EXPECT_EQ(lookup.value().ToString(), bob_pseudo.ToString());                                                                                                                         
 }                                                                                                                                                                                      
                                                                                                                                                                                        
 }  // namespace                                                                                                                                                                        
 }  // namespace f2chat                                                                                                                                                                 
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 **Test Coverage Goals:**                                                                                                                                                               
 - Unit tests: 100% coverage for crypto primitives                                                                                                                                      
 - Integration tests: End-to-end message flow                                                                                                                                           
 - Performance benchmarks: Latency targets documented                                                                                                                                   
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ### 4. Documentation Standards                                                                                                                                                         
                                                                                                                                                                                        
 **Every file must have:**                                                                                                                                                              
 1. File-level comment (purpose, authors, date)                                                                                                                                         
 2. Class-level comment (what it does, thread safety, performance)                                                                                                                      
 3. Method-level comment (args, returns, performance)                                                                                                                                   
                                                                                                                                                                                        
 **Example:**                                                                                                                                                                           
 ```cpp                                                                                                                                                                                 
 // lib/crypto/fhe_operations.h                                                                                                                                                         
 //                                                                                                                                                                                     
 // FHE operations for spam detection (Halevi-Shoup SIMD batching).                                                                                                                     
 //                                                                                                                                                                                     
 // This library implements manual SIMD optimization for duplicate detection,                                                                                                           
 // achieving O(log N) complexity via binary reduction. This is faster than                                                                                                             
 // naive O(N²) comparison and competitive with compiler-generated code.                                                                                                                
 //                                                                                                                                                                                     
 // Author: f2chat team                                                                                                                                                                 
 // Date: 2025-10-29                                                                                                                                                                    
                                                                                                                                                                                        
 #ifndef F2CHAT_LIB_CRYPTO_FHE_OPERATIONS_H_                                                                                                                                            
 #define F2CHAT_LIB_CRYPTO_FHE_OPERATIONS_H_                                                                                                                                            
                                                                                                                                                                                        
 namespace f2chat {                                                                                                                                                                     
                                                                                                                                                                                        
 // FHE operations for encrypted metadata spam detection.                                                                                                                               
 //                                                                                                                                                                                     
 // Thread Safety: This class is thread-safe. Multiple threads can call                                                                                                                 
 // EvalEqual, SumAllSlots concurrently.                                                                                                                                                
 //                                                                                                                                                                                     
 // Performance Notes:                                                                                                                                                                  
 // - EvalEqual: ~10ms per operation                                                                                                                                                    
 // - SumAllSlots: O(log N) rotations (13 rotations for 8192 slots, ~130ms)                                                                                                             
 // - Total spam detection (1000 records): ~5 seconds                                                                                                                                   
 class FheOperations {                                                                                                                                                                  
  public:                                                                                                                                                                               
   // Encrypted equality check: Returns 1 if ct1 == ct2, else 0.                                                                                                                        
   //                                                                                                                                                                                   
   // Algorithm: (a - b)^(p-1) mod p (Fermat's Little Theorem)                                                                                                                          
   //                                                                                                                                                                                   
   // Args:                                                                                                                                                                             
   //   ct1: First ciphertext                                                                                                                                                           
   //   ct2: Second ciphertext                                                                                                                                                          
   //   crypto_context: OpenFHE context                                                                                                                                                 
   //                                                                                                                                                                                   
   // Returns:                                                                                                                                                                          
   //   Ciphertext containing 1 (equal) or 0 (not equal)                                                                                                                                
   //   Error status if FHE operation fails                                                                                                                                             
   //                                                                                                                                                                                   
   // Performance: ~10ms (single operation)                                                                                                                                             
   static absl::StatusOr<lbcrypto::Ciphertext> EvalEqual(                                                                                                                               
       const lbcrypto::Ciphertext& ct1,                                                                                                                                                 
       const lbcrypto::Ciphertext& ct2,                                                                                                                                                 
       const lbcrypto::CryptoContext& crypto_context);                                                                                                                                  
                                                                                                                                                                                        
   // Sum across all SIMD slots (Halevi-Shoup binary reduction).                                                                                                                        
   //                                                                                                                                                                                   
   // Algorithm: O(log N) rotations + additions                                                                                                                                         
   //   For N=8192 slots: 13 rotations (log₂(8192) = 13)                                                                                                                                
   //                                                                                                                                                                                   
   // Args:                                                                                                                                                                             
   //   ct: Ciphertext with SIMD slots                                                                                                                                                  
   //   crypto_context: OpenFHE context                                                                                                                                                 
   //                                                                                                                                                                                   
   // Returns:                                                                                                                                                                          
   //   Ciphertext where slot 0 = sum of all original slots                                                                                                                             
   //   Error status if rotation fails                                                                                                                                                  
   //                                                                                                                                                                                   
   // Performance: ~130ms for 8192 slots (13 rotations × 10ms each)                                                                                                                     
   static absl::StatusOr<lbcrypto::Ciphertext> SumAllSlots(                                                                                                                             
       const lbcrypto::Ciphertext& ct,                                                                                                                                                  
       const lbcrypto::CryptoContext& crypto_context);                                                                                                                                  
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 }  // namespace f2chat                                                                                                                                                                 
                                                                                                                                                                                        
 #endif  // F2CHAT_LIB_CRYPTO_FHE_OPERATIONS_H_                                                                                                                                         
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ## OpenFHE Integration                                                                                                                                                                 
                                                                                                                                                                                        
 ### Installation (System-Level)                                                                                                                                                        
                                                                                                                                                                                        
 ```bash                                                                                                                                                                                
 # Ubuntu/Debian                                                                                                                                                                        
 git clone https://github.com/openfheorg/openfhe-development                                                                                                                            
 cd openfhe-development                                                                                                                                                                 
 mkdir build && cd build                                                                                                                                                                
 cmake -DCMAKE_INSTALL_PREFIX=/usr/local \                                                                                                                                              
       -DCMAKE_BUILD_TYPE=Release \                                                                                                                                                     
       -DBUILD_SHARED=ON \                                                                                                                                                              
       ..                                                                                                                                                                               
 make -j$(nproc)                                                                                                                                                                        
 sudo make install                                                                                                                                                                      
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 ### Bazel Integration                                                                                                                                                                  
                                                                                                                                                                                        
 ```python                                                                                                                                                                              
 # third_party/openfhe/BUILD.bazel                                                                                                                                                      
 cc_library(                                                                                                                                                                            
     name = "openfhe",                                                                                                                                                                  
     hdrs = glob([                                                                                                                                                                      
         "/usr/local/include/openfhe/**/*.h",                                                                                                                                           
     ]),                                                                                                                                                                                
     includes = [                                                                                                                                                                       
         "/usr/local/include/openfhe",                                                                                                                                                  
         "/usr/local/include/openfhe/core",                                                                                                                                             
         "/usr/local/include/openfhe/pke",                                                                                                                                              
     ],                                                                                                                                                                                 
     linkopts = [                                                                                                                                                                       
         "-L/usr/local/lib",                                                                                                                                                            
         "-lOPENFHEcore",                                                                                                                                                               
         "-lOPENFHEpke",                                                                                                                                                                
     ],                                                                                                                                                                                 
     visibility = ["//visibility:public"],                                                                                                                                              
 )                                                                                                                                                                                      
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 ### BGV Parameters                                                                                                                                                                     
                                                                                                                                                                                        
 ```cpp                                                                                                                                                                                 
 // lib/util/fhe_params.h                                                                                                                                                               
 namespace f2chat {                                                                                                                                                                     
                                                                                                                                                                                        
 struct FheParams {                                                                                                                                                                     
   static constexpr int kRingDimension = 8192;   // SIMD slots                                                                                                                          
   static constexpr int kPlaintextModulus = 65537; // Prime for integers                                                                                                                
   static constexpr int kSecurityLevel = 128;    // Bits                                                                                                                                
   static constexpr int kMultiplicativeDepth = 3; // For (a-b)^(p-1)                                                                                                                    
 };                                                                                                                                                                                     
                                                                                                                                                                                        
 // Helper to create BGV context                                                                                                                                                        
 lbcrypto::CryptoContext CreateBGVContext() {                                                                                                                                           
   lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS> parameters;                                                                                                                        
   parameters.SetMultiplicativeDepth(FheParams::kMultiplicativeDepth);                                                                                                                  
   parameters.SetPlaintextModulus(FheParams::kPlaintextModulus);                                                                                                                        
   parameters.SetRingDim(FheParams::kRingDimension);                                                                                                                                    
   parameters.SetSecurityLevel(lbcrypto::HEStd_128_classic);                                                                                                                            
                                                                                                                                                                                        
   return lbcrypto::GenCryptoContext(parameters);                                                                                                                                       
 }                                                                                                                                                                                      
                                                                                                                                                                                        
 }  // namespace f2chat                                                                                                                                                                 
 ```                                                                                                                                                                                    
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ## Threat Model                                                                                                                                                                        
                                                                                                                                                                                        
 ### Adversaries                                                                                                                                                                        
                                                                                                                                                                                        
 **1. Semi-Trusted Server (Honest-but-Curious)**                                                                                                                                        
 - Follows protocol but tries to learn identities                                                                                                                                       
 - Has FHE public key, can encrypt/compute                                                                                                                                              
 - Does NOT have secret key (cannot decrypt metadata)                                                                                                                                   
 - **Mitigation:** FHE prevents server from seeing pseudonyms                                                                                                                           
                                                                                                                                                                                        
 **2. Edge Function Providers (k-1 Compromised)**                                                                                                                                       
 - Adversary controls k-1 of n providers (e.g., AWS + Google, but not Cloudflare)                                                                                                       
 - Can see partial decryptions, but need k to recover plaintext                                                                                                                         
 - **Mitigation:** Threshold requires k=3 (cannot decrypt with 2)                                                                                                                       
                                                                                                                                                                                        
 **3. Government Coercion (Single Jurisdiction)**                                                                                                                                       
 - Government subpoenas one cloud provider (e.g., US subpoenas AWS)                                                                                                                     
 - Provider must give up threshold share                                                                                                                                                
 - **Mitigation:** Jurisdictional diversity (AWS in US, Google in EU, Cloudflare global)                                                                                                
                                                                                                                                                                                        
 **4. Device Compromise**                                                                                                                                                               
 - Adversary steals user's device                                                                                                                                                       
 - Can access identity mapping (pseudonym ↔ real ID)                                                                                                                                    
 - **Mitigation:** Device encryption, forward secrecy (past messages unlinkable)                                                                                                        
                                                                                                                                                                                        
 ### Security Guarantees                                                                                                                                                                
                                                                                                                                                                                        
 1. **Metadata Privacy:** Server cannot see real identities (only pseudonyms)                                                                                                           
 2. **Threshold Security:** k-1 edge functions cannot decrypt (need k=3)                                                                                                                
 3. **Jurisdictional Resistance:** Single government cannot coerce all k providers                                                                                                      
 4. **Forward Secrecy:** Pseudonym rotation prevents linking past messages                                                                                                              
 5. **Spam Detection Privacy:** Server learns "spam count", not individual spammers                                                                                                     
                                                                                                                                                                                        
 ### Limitations (Acknowledge in Paper)                                                                                                                                                 
                                                                                                                                                                                        
 1. **Pseudonym Rotation Leaks:** If Alice rotates Pseudo_A → Pseudo_B, server may link (timing correlation)                                                                            
 2. **PIR Bandwidth:** Download-all PIR has O(N) bandwidth (vs O(1) for revealing mailbox)                                                                                              
 3. **No Multi-Key FHE:** Server still has global FHE key (future work: each user has own key)                                                                                          
 4. **Timing Attacks:** Traffic analysis may reveal communication patterns (mix networks help)                                                                                          
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ## Performance Targets                                                                                                                                                                 
                                                                                                                                                                                        
 ### Latency (Per Operation)                                                                                                                                                            
                                                                                                                                                                                        
 | Operation | Target | Measured | Notes |                                                                                                                                              
 |-----------|--------|----------|-------|                                                                                                                                              
 | **Client: Generate pseudonym** | <10ms | TBD | One-time setup |                                                                                                                      
 | **Client: Encrypt metadata (FHE)** | 50-100ms | TBD | Per message |                                                                                                                  
 | **Client: Encrypt content (threshold)** | 10-50ms | TBD | Per message |                                                                                                              
 | **Server: Batch 1000 metadata** | <100ms | TBD | SIMD packing |                                                                                                                      
 | **Server: Spam detection (FHE)** | 2-5s | TBD | 1000-record batch |                                                                                                                  
 | **Edge: Threshold decrypt (cold)** | 800-1200ms | TBD | Cold start Lambda |                                                                                                          
 | **Edge: Threshold decrypt (warm)** | 100-150ms | TBD | Warm Lambda |                                                                                                                 
 | **Client: PIR query** | <5s | TBD | 1000-message mailbox |                                                                                                                           
 | **End-to-end (send → alert)** | 3-10s | TBD | Acceptable for spam |                                                                                                                  
                                                                                                                                                                                        
 ### Throughput                                                                                                                                                                         
                                                                                                                                                                                        
 | Metric | Target | Measured |                                                                                                                                                         
 |--------|--------|----------|                                                                                                                                                         
 | **Server: Messages/hour** | 100,000+ | TBD |                                                                                                                                         
 | **Server: Batches/hour** | 100+ | TBD |                                                                                                                                              
 | **Edge: Decryptions/hour** | 1000+ | TBD |                                                                                                                                           
                                                                                                                                                                                        
 ### Cost (1M Users, 1M Messages/Day)                                                                                                                                                   
                                                                                                                                                                                        
 | Component | Cost/Month | Notes |                                                                                                                                                     
 |-----------|------------|-------|                                                                                                                                                     
 | **AWS Lambda (Share 1)** | $0.50 | 100 invocations/day × $0.20/million |                                                                                                             
 | **Google Cloud (Share 2)** | $0.50 | Similar |                                                                                                                                       
 | **Cloudflare (Share 3)** | $0.50 | 100K requests free, then $0.50/million |                                                                                                          
 | **Storage (metadata)** | $0.60 | 30GB × $0.02/GB |                                                                                                                                   
 | **Bandwidth** | $1.00 | 100GB × $0.01/GB |                                                                                                                                           
 | **Total** | **$3.10** | vs $1700 for dedicated servers |                                                                                                                             
                                                                                                                                                                                        
 **Cost Reduction: 548× cheaper**                                                                                                                                                       
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ## Validation Checklist                                                                                                                                                                
                                                                                                                                                                                        
 ### Phase 1 Validation                                                                                                                                                                 
 - [ ] Bazel build succeeds with `-Werror`                                                                                                                                              
 - [ ] All unit tests pass                                                                                                                                                              
 - [ ] Can generate pseudonyms (unlinkable)                                                                                                                                             
 - [ ] Can encrypt metadata with FHE                                                                                                                                                    
 - [ ] Can serialize/deserialize metadata                                                                                                                                               
                                                                                                                                                                                        
 ### Phase 2 Validation                                                                                                                                                                 
 - [ ] Spam detection detects duplicates correctly                                                                                                                                      
 - [ ] SIMD speedup: ≥100× vs naive                                                                                                                                                     
 - [ ] Latency: <5s for 1000-record batch                                                                                                                                               
 - [ ] False positives: <1%                                                                                                                                                             
 - [ ] False negatives: <1%                                                                                                                                                             
                                                                                                                                                                                        
 ### Phase 3 Validation                                                                                                                                                                 
 - [ ] Threshold requires exactly k=3 shares                                                                                                                                            
 - [ ] k-1 shares cannot decrypt                                                                                                                                                        
 - [ ] Partial decryptions combine correctly                                                                                                                                            
 - [ ] Latency overhead: <2× vs single-key                                                                                                                                              
                                                                                                                                                                                        
 ### Phase 4 Validation                                                                                                                                                                 
 - [ ] AWS Lambda deploys successfully                                                                                                                                                  
 - [ ] Google Cloud Function deploys successfully                                                                                                                                       
 - [ ] Cloudflare Worker deploys successfully                                                                                                                                           
 - [ ] Edge coordinator invokes k functions                                                                                                                                             
 - [ ] Cold start: <1 second                                                                                                                                                            
 - [ ] Warm start: <150ms                                                                                                                                                               
 - [ ] Cost tracking: <$3/month                                                                                                                                                         
                                                                                                                                                                                        
 ### Phase 5 Validation                                                                                                                                                                 
 - [ ] PIR query doesn't reveal mailbox                                                                                                                                                 
 - [ ] Bandwidth overhead: <10× vs naive                                                                                                                                                
 - [ ] Latency: <5s for 1000-message mailbox                                                                                                                                            
                                                                                                                                                                                        
 ### Phase 6 Validation                                                                                                                                                                 
 - [ ] Docker Compose deploys successfully                                                                                                                                              
 - [ ] CLI client sends/receives messages                                                                                                                                               
 - [ ] gRPC server handles 100K messages/hour                                                                                                                                           
 - [ ] PostgreSQL stores encrypted metadata                                                                                                                                             
 - [ ] Spam alerts display correctly                                                                                                                                                    
                                                                                                                                                                                        
 ### Phase 7 Validation                                                                                                                                                                 
 - [ ] Paper draft complete (12-15 pages)                                                                                                                                               
 - [ ] All benchmarks run and documented                                                                                                                                                
 - [ ] Code open-sourced on GitHub                                                                                                                                                      
 - [ ] arXiv preprint submitted                                                                                                                                                         
 - [ ] Conference submission (USENIX/CCS/NDSS)                                                                                                                                          
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ## Key Principles                                                                                                                                                                      
                                                                                                                                                                                        
 ### 1. Privacy First                                                                                                                                                                   
 - **Metadata is more sensitive than content** (NSA PRISM proves this)                                                                                                                  
 - Server should learn **nothing** about real identities                                                                                                                                
 - Threshold decryption minimizes trust in any single party                                                                                                                             
                                                                                                                                                                                        
 ### 2. Performance Matters                                                                                                                                                             
 - FHE is expensive, use it **only where necessary** (metadata, not content)                                                                                                            
 - SIMD batching is **critical** for scalability (100,000× speedup)                                                                                                                     
 - Edge functions must be fast (warm latency <150ms)                                                                                                                                    
                                                                                                                                                                                        
 ### 3. Cost Efficiency                                                                                                                                                                 
 - **1000× cost reduction** is the key innovation (serverless vs dedicated)                                                                                                             
 - Measure actual cloud costs (Lambda invocations, storage, bandwidth)                                                                                                                  
 - Optimize for cold start latency (pre-warm functions if needed)                                                                                                                       
                                                                                                                                                                                        
 ### 4. Research Rigor                                                                                                                                                                  
 - Document **every design decision** (why FHE for metadata, not content)                                                                                                               
 - Measure **everything** (latency, throughput, cost)                                                                                                                                   
 - Acknowledge **limitations** (pseudonym rotation leaks, PIR bandwidth)                                                                                                                
                                                                                                                                                                                        
 ### 5. Code Quality                                                                                                                                                                    
 - Follow **Google C++ Style Guide** strictly                                                                                                                                           
 - Use **Abseil StatusOr** for all error handling                                                                                                                                       
 - Write **comprehensive tests** (unit, integration, benchmarks)                                                                                                                        
 - Document **performance implications** in every method                                                                                                                                
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ## Expected Challenges                                                                                                                                                                 
                                                                                                                                                                                        
 ### 1. OpenFHE Integration                                                                                                                                                             
 - **Challenge:** Bazel + system-installed OpenFHE can be tricky                                                                                                                        
 - **Solution:** Use `third_party/openfhe/BUILD.bazel` wrapper                                                                                                                          
 - **Fallback:** Fetch OpenFHE via `http_archive` in MODULE.bazel                                                                                                                       
                                                                                                                                                                                        
 ### 2. FHE Performance                                                                                                                                                                 
 - **Challenge:** FHE operations are slow (50-100ms per encrypt)                                                                                                                        
 - **Solution:** SIMD batching (8192 operations in parallel)                                                                                                                            
 - **Monitoring:** Profile with `perf` or OpenFHE's built-in timers                                                                                                                     
                                                                                                                                                                                        
 ### 3. Threshold Key Distribution                                                                                                                                                      
 - **Challenge:** How to securely distribute shares to edge functions                                                                                                                   
 - **Solution:** Use cloud secrets managers (AWS Secrets Manager, etc.)                                                                                                                 
 - **Security:** Rotate shares periodically (e.g., monthly)                                                                                                                             
                                                                                                                                                                                        
 ### 4. PIR Bandwidth                                                                                                                                                                   
 - **Challenge:** Download-all PIR has high bandwidth                                                                                                                                   
 - **Solution:** Start with download-all, optimize with ORAM later                                                                                                                      
 - **Alternative:** Accept the tradeoff (privacy > bandwidth)                                                                                                                           
                                                                                                                                                                                        
 ### 5. Pseudonym Rotation Linkability                                                                                                                                                  
 - **Challenge:** Server may link old → new pseudonyms (timing)                                                                                                                         
 - **Solution:** Add noise to rotation timing, batch rotations                                                                                                                          
 - **Future Work:** Mixnet-based rotation (hide timing)                                                                                                                                 
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 ## Success Criteria                                                                                                                                                                    
                                                                                                                                                                                        
 ### Research Success                                                                                                                                                                   
 - ✅ Paper accepted to USENIX Security, CCS, or NDSS                                                                                                                                    
 - ✅ Cited by follow-up work on FHE metadata privacy                                                                                                                                    
 - ✅ Adopted by privacy-focused messaging projects                                                                                                                                      
                                                                                                                                                                                        
 ### Technical Success                                                                                                                                                                  
 - ✅ Spam detection: <5s for 1000-record batch                                                                                                                                          
 - ✅ Threshold decryption: AWS + Google + Cloudflare deployment                                                                                                                         
 - ✅ Cost: <$3/month for 1M users (1000× cheaper than federated)                                                                                                                        
 - ✅ SIMD speedup: ≥100× vs naive                                                                                                                                                       
                                                                                                                                                                                        
 ### Impact Success                                                                                                                                                                     
 - ✅ Demonstrate FHE metadata privacy is practical                                                                                                                                      
 - ✅ Prove serverless threshold scales (cost + latency)                                                                                                                                 
 - ✅ Influence policy debate (vs metadata collection)                                                                                                                                   
                                                                                                                                                                                        
 ---                                                                                                                                                                                    
                                                                                                                                                                                        
 
