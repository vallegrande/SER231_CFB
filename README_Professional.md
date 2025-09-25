# CFB (Cipher Feedback) Mode - Professional Analysis

## 📋 Table of Contents
1. [How CFB Works - Technical Deep Dive](#how-cfb-works)
2. [When to Use CFB - Application Scenarios](#when-to-use-cfb)
3. [CFB Weaknesses - Critical Limitations](#cfb-weaknesses)
4. [Professional Recommendations](#professional-recommendations)

---

## 🔧 How CFB Works - Technical Deep Dive

### Overview
**Cipher Feedback (CFB)** transforms a block cipher like AES into a stream cipher by using the cipher's output as a feedback mechanism. This enables encryption of data streams of arbitrary length without padding requirements.

### Step-by-Step Technical Process

#### 1. **Initialization Phase**
```
Initial State:
┌─────────────────┐
│ Shift Register  │ ← Loaded with IV (128 bits for AES)
│   (128 bits)    │
└─────────────────┘
```

#### 2. **Encryption Process (CFB-8 Implementation)**

```java
// Our implementation uses CFB-8 (8-bit segments)
private static final String TRANSFORMATION = "AES/CFB8/NoPadding";
```

**Step-by-step encryption:**

```
Step 1: Encrypt the shift register content
┌─────────────────┐    ┌─────────────┐    ┌─────────────────┐
│ Shift Register  │───→│ AES Encrypt │───→│   Output Block  │
│   (128 bits)    │    │             │    │   (128 bits)    │
└─────────────────┘    └─────────────┘    └─────────────────┘

Step 2: Extract feedback segment (8 bits)
┌─────────────────┐
│   Output Block  │
│   [87654321]    │ ← Take leftmost 8 bits
└─────────────────┘

Step 3: XOR with plaintext
[P₁] ⊕ [87654321] = [C₁]  ← Ciphertext byte

Step 4: Update shift register
┌─────────────────┐    ┌─────────────────┐
│ Old Register    │───→│ New Register    │
│ [old_data...]   │    │ [old_data<<8|C₁]│ ← Shift left, insert C₁
└─────────────────┘    └─────────────────┘
```

#### 3. **Practical Implementation Example**

```java
public static byte[] encrypt(String plaintext, SecretKey key, byte[] iv) throws Exception {
    // 1. Create and configure cipher
    Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
    
    // 2. Initialize with key and IV
    cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
    
    // 3. Process data (CFB handles the feedback internally)
    return cipher.doFinal(plaintext.getBytes("UTF-8"));
}
```

#### 4. **Mathematical Representation**

For CFB-s (s-bit feedback):
```
C₁ = P₁ ⊕ MSBₛ(Eₖ(IV))
C₂ = P₂ ⊕ MSBₛ(Eₖ(LSB₁₂₈₋ₛ(IV) || C₁))
C₃ = P₃ ⊕ MSBₛ(Eₖ(LSB₁₂₈₋ₛ(LSB₁₂₈₋ₛ(IV) || C₁) || C₂))
...
```

Where:
- `Pᵢ` = Plaintext segment i
- `Cᵢ` = Ciphertext segment i  
- `Eₖ` = AES encryption with key k
- `MSBₛ` = Most significant s bits
- `LSB₁₂₈₋ₛ` = Least significant (128-s) bits

#### 5. **Decryption Process**

```java
public static String decrypt(byte[] ciphertext, SecretKey key, byte[] iv) throws Exception {
    // CFB decryption uses the same encryption operation
    Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
    
    // The only difference is the mode
    cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
    
    byte[] decryptedBytes = cipher.doFinal(ciphertext);
    return new String(decryptedBytes, "UTF-8");
}
```

#### 6. **Key Characteristics Demonstrated**

**Example from our implementation:**
```java
// Demo 4 - Different IVs produce different outputs
String message = "Same message, different results";
SecretKey key = CFBCipher.generateKey();

for (int i = 1; i <= 3; i++) {
    byte[] iv = CFBCipher.generateIV();  // Different IV each time
    byte[] encrypted = CFBCipher.encrypt(message, key, iv);
    
    System.out.println("Attempt " + i + ":");
    System.out.println("  IV (hex): " + bytesToHex(iv));
    System.out.println("  Encrypted (hex): " + bytesToHex(encrypted));
}
```

**Output demonstrates:**
- Same plaintext + Same key + Different IV = Completely different ciphertext
- This proves CFB's security against pattern analysis

---

## 🎯 When to Use CFB - Application Scenarios

### Primary Use Cases

#### 1. **Real-Time Data Streaming**

**Scenario:** Live video/audio encryption for secure communications

```java
// CFB excels in streaming because it doesn't need complete blocks
public class StreamEncryption {
    public void encryptStream(InputStream input, OutputStream output) {
        // CFB can encrypt byte-by-byte as data arrives
        int byteData;
        while ((byteData = input.read()) != -1) {
            byte[] singleByte = {(byte) byteData};
            byte[] encrypted = CFBCipher.encrypt(new String(singleByte), key, iv);
            output.write(encrypted);
        }
    }
}
```

**Why CFB is ideal:**
- ✅ No waiting for complete 16-byte blocks
- ✅ Immediate processing as data arrives
- ✅ Constant memory usage regardless of stream size

#### 2. **Network Protocol Encryption**

**Scenario:** Secure communication protocols (SSH, TLS alternatives)

```java
// Example: Secure message protocol
public class SecureProtocol {
    public void sendSecureMessage(String message, Socket socket) throws Exception {
        // Generate unique IV for each message
        byte[] iv = CFBCipher.generateIV();
        
        // Encrypt message
        byte[] encrypted = CFBCipher.encrypt(message, sessionKey, iv);
        
        // Send IV + encrypted data
        socket.getOutputStream().write(iv);  // IV can be public
        socket.getOutputStream().write(encrypted);
    }
}
```

**Advantages for networking:**
- ✅ Self-synchronizing after error recovery
- ✅ No padding overhead (saves bandwidth)
- ✅ Immediate error detection and recovery

#### 3. **Database Field Encryption**

**Scenario:** Encrypting sensitive database fields of varying lengths

```java
public class DatabaseEncryption {
    public void encryptUserData(User user) throws Exception {
        // Each field gets unique IV
        user.setEncryptedSSN(encryptField(user.getSSN()));
        user.setEncryptedCreditCard(encryptField(user.getCreditCard()));
        user.setEncryptedAddress(encryptField(user.getAddress()));
    }
    
    private String encryptField(String plaintext) throws Exception {
        byte[] iv = CFBCipher.generateIV();
        byte[] encrypted = CFBCipher.encrypt(plaintext, dbKey, iv);
        
        // Store IV + encrypted data together
        return CFBCipher.bytesToBase64(iv) + ":" + CFBCipher.bytesToBase64(encrypted);
    }
}
```

**Why CFB works well:**
- ✅ No padding reveals field length information
- ✅ Each record has unique encryption (different IVs)
- ✅ Efficient storage (ciphertext = plaintext length)

#### 4. **IoT Device Communications**

**Scenario:** Resource-constrained devices with limited memory

```java
public class IoTSensor {
    private static final int BUFFER_SIZE = 8; // Very small buffer
    
    public void transmitSensorData(float temperature, float humidity) throws Exception {
        String data = String.format("T:%.1f,H:%.1f", temperature, humidity);
        
        // CFB can work with tiny buffers
        byte[] iv = CFBCipher.generateIV();
        byte[] encrypted = CFBCipher.encrypt(data, deviceKey, iv);
        
        transmitToGateway(iv, encrypted);
    }
}
```

**CFB advantages for IoT:**
- ✅ Low memory footprint
- ✅ No need to buffer entire messages
- ✅ Efficient for small data packets

### Decision Matrix: When to Choose CFB

| Requirement | CFB Suitability | Alternative |
|-------------|-----------------|-------------|
| **Stream processing** | ✅ Excellent | CTR mode |
| **Variable length data** | ✅ Perfect | CBC with padding |
| **Real-time requirements** | ✅ Ideal | GCM (if auth needed) |
| **Low memory environments** | ✅ Great | ChaCha20 |
| **Network protocols** | ✅ Good | TLS built-ins |
| **Error recovery** | ✅ Self-healing | Forward Error Correction |
| **Legacy system integration** | ✅ Compatible | System-specific |

### Professional Implementation Guidelines

#### Configuration Recommendations:

```java
// Production-ready configuration
public class ProductionCFB {
    // Use CFB8 for byte-level processing
    private static final String TRANSFORMATION = "AES/CFB8/NoPadding";
    
    // 256-bit keys for maximum security
    private static final int KEY_SIZE = 256;
    
    // Always use SecureRandom
    private static final SecureRandom secureRandom = new SecureRandom();
    
    public static class EncryptionResult {
        public final byte[] iv;
        public final byte[] ciphertext;
        
        public EncryptionResult(byte[] iv, byte[] ciphertext) {
            this.iv = iv.clone();
            this.ciphertext = ciphertext.clone();
        }
    }
    
    public static EncryptionResult encryptMessage(String message, SecretKey key) 
            throws Exception {
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        
        byte[] encrypted = CFBCipher.encrypt(message, key, iv);
        return new EncryptionResult(iv, encrypted);
    }
}
```

---

## ⚠️ CFB Weaknesses - Critical Limitations

### 1. **Sequential Processing Limitation**

#### Problem Description:
CFB encryption cannot be parallelized because each ciphertext block depends on the previous one.

```java
// This CANNOT be parallelized:
for (int i = 0; i < plaintextBlocks.length; i++) {
    // Block i depends on ciphertext from block i-1
    ciphertext[i] = encrypt(plaintext[i], getShiftRegister(i-1));
}

// Compare with CTR mode (parallelizable):
IntStream.range(0, plaintextBlocks.length).parallel().forEach(i -> {
    // Each block is independent
    ciphertext[i] = encrypt(plaintext[i], counter + i);
});
```

#### Performance Impact:
```java
// Benchmark comparison (hypothetical)
public class PerformanceBenchmark {
    public void benchmarkModes() {
        // CFB: Sequential only
        long cfbTime = measureCFBEncryption(largeData);      // ~1000ms
        
        // CTR: Parallel processing
        long ctrTime = measureCTREncryption(largeData);      // ~250ms (4 cores)
        
        System.out.println("CFB vs CTR speedup: " + (cfbTime / ctrTime) + "x slower");
    }
}
```

#### Mitigation Strategies:
```java
// Strategy 1: Use CFB for small data, CTR for large data
public byte[] smartEncrypt(byte[] data, SecretKey key) {
    if (data.length < 1024) {
        return useCFB(data, key);  // Small data: CFB is fine
    } else {
        return useCTR(data, key);  // Large data: Use parallel CTR
    }
}

// Strategy 2: Pipeline processing for streams
public class PipelinedCFB {
    private final BlockingQueue<byte[]> encryptionQueue = new ArrayBlockingQueue<>(100);
    
    public void pipelineEncrypt(InputStream input) {
        // Producer: Read data
        CompletableFuture.runAsync(() -> readDataToQueue(input));
        
        // Consumer: Encrypt sequentially but overlap I/O
        CompletableFuture.runAsync(() -> encryptFromQueue());
    }
}
```

### 2. **Error Propagation Vulnerability**

#### Problem Description:
A single-bit error in CFB ciphertext corrupts multiple plaintext blocks.

```java
// Demonstrating error propagation
public class ErrorPropagationDemo {
    public void demonstrateErrorPropagation() throws Exception {
        String original = "This is a test message for error propagation demonstration";
        
        // Encrypt normally
        byte[] iv = CFBCipher.generateIV();
        byte[] encrypted = CFBCipher.encrypt(original, key, iv);
        
        // Introduce single-bit error
        encrypted[10] ^= 0x01;  // Flip one bit
        
        // Decrypt and observe corruption
        String corrupted = CFBCipher.decrypt(encrypted, key, iv);
        
        analyzeCorruption(original, corrupted);
    }
    
    private void analyzeCorruption(String original, String corrupted) {
        // CFB-8: Error affects current byte + next 16 bytes (worst case)
        System.out.println("Original: " + original);
        System.out.println("Corrupted: " + corrupted);
        System.out.println("Error span: ~17 bytes maximum");
    }
}
```

#### Error Recovery Implementation:
```java
public class CFBWithErrorRecovery {
    private static final int MAX_ERROR_SPAN = 17; // CFB-8 worst case
    
    public String decryptWithRecovery(byte[] ciphertext, SecretKey key, byte[] iv) {
        try {
            return CFBCipher.decrypt(ciphertext, key, iv);
        } catch (Exception e) {
            // Attempt error recovery by skipping corrupted segments
            return attemptErrorRecovery(ciphertext, key, iv);
        }
    }
    
    private String attemptErrorRecovery(byte[] ciphertext, SecretKey key, byte[] iv) {
        // Implementation would try decrypting from multiple starting points
        // to find uncorrupted segments
        // This is complex and application-specific
        return "Error recovery implementation...";
    }
}
```

### 3. **Synchronization Dependency**

#### Problem Description:
CFB requires perfect synchronization between sender and receiver. Loss of synchronization corrupts all subsequent data.

```java
// Vulnerable to synchronization loss
public class SynchronizationIssue {
    public void demonstrateSyncLoss() throws Exception {
        String message = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        
        // Encrypt normally
        byte[] encrypted = CFBCipher.encrypt(message, key, iv);
        
        // Simulate lost byte during transmission
        byte[] corruptedTransmission = new byte[encrypted.length - 1];
        System.arraycopy(encrypted, 1, corruptedTransmission, 0, encrypted.length - 1);
        
        // Decryption fails catastrophically
        try {
            String result = CFBCipher.decrypt(corruptedTransmission, key, iv);
            System.out.println("Result: " + result); // Completely garbled
        } catch (Exception e) {
            System.out.println("Decryption failed: " + e.getMessage());
        }
    }
}
```

#### Synchronization Protection:
```java
public class ProtectedCFBProtocol {
    private static final byte[] SYNC_MARKER = "SYNC".getBytes();
    
    public byte[] createSecurePacket(String message) throws Exception {
        byte[] iv = CFBCipher.generateIV();
        byte[] encrypted = CFBCipher.encrypt(message, key, iv);
        
        // Add synchronization markers and length headers
        ByteArrayOutputStream packet = new ByteArrayOutputStream();
        packet.write(SYNC_MARKER);                    // Sync marker
        packet.write(ByteBuffer.allocate(4).putInt(iv.length).array());  // IV length
        packet.write(iv);                             // IV
        packet.write(ByteBuffer.allocate(4).putInt(encrypted.length).array()); // Data length
        packet.write(encrypted);                      // Encrypted data
        packet.write(SYNC_MARKER);                    // End marker
        
        return packet.toByteArray();
    }
}
```

### 4. **IV Management Complexity**

#### Problem Description:
CFB requires unique IVs for every message, creating management overhead.

```java
// Poor IV management (DANGEROUS)
public class PoorIVManagement {
    private static byte[] globalIV = new byte[16]; // NEVER DO THIS
    
    public byte[] encryptMessage(String message) throws Exception {
        // Reusing IV is cryptographically broken
        return CFBCipher.encrypt(message, key, globalIV);
    }
}

// Proper IV management (COMPLEX)
public class ProperIVManagement {
    private final Map<String, Long> userCounters = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    
    public EncryptionResult encryptForUser(String userId, String message) throws Exception {
        // Strategy 1: Counter-based IV (requires state management)
        Long counter = userCounters.compute(userId, (k, v) -> (v == null) ? 1L : v + 1);
        byte[] iv = generateCounterIV(userId, counter);
        
        // Strategy 2: Random IV (simpler but larger overhead)
        // byte[] iv = new byte[16];
        // random.nextBytes(iv);
        
        byte[] encrypted = CFBCipher.encrypt(message, key, iv);
        return new EncryptionResult(iv, encrypted);
    }
    
    private byte[] generateCounterIV(String userId, long counter) {
        // Combine user ID hash + counter to ensure uniqueness
        byte[] iv = new byte[16];
        // Implementation details...
        return iv;
    }
}
```

### 5. **Lack of Authentication**

#### Problem Description:
CFB provides only confidentiality, not authenticity or integrity.

```java
// Vulnerable to tampering
public class UnauthenticatedCFB {
    public void demonstrateVulnerability() throws Exception {
        String originalMessage = "Transfer $100 to Alice";
        
        // Encrypt message
        byte[] iv = CFBCipher.generateIV();
        byte[] encrypted = CFBCipher.encrypt(originalMessage, key, iv);
        
        // Attacker modifies ciphertext (changes Alice to Bob)
        // This is possible because CFB doesn't detect tampering
        byte[] tamperedCiphertext = tamperWithCiphertext(encrypted);
        
        // Decryption succeeds but produces wrong plaintext
        String tamperedMessage = CFBCipher.decrypt(tamperedCiphertext, key, iv);
        System.out.println("Tampered: " + tamperedMessage); // "Transfer $100 to Bob"
    }
}

// Secure implementation with authentication
public class AuthenticatedCFB {
    public EncryptionResult encryptWithAuth(String message) throws Exception {
        // Step 1: Generate IV and encrypt
        byte[] iv = CFBCipher.generateIV();
        byte[] ciphertext = CFBCipher.encrypt(message, key, iv);
        
        // Step 2: Generate HMAC for authentication
        byte[] authTag = generateHMAC(iv, ciphertext, authKey);
        
        return new EncryptionResult(iv, ciphertext, authTag);
    }
    
    public String decryptWithVerification(EncryptionResult result) throws Exception {
        // Step 1: Verify HMAC
        if (!verifyHMAC(result.iv, result.ciphertext, result.authTag, authKey)) {
            throw new SecurityException("Message authentication failed");
        }
        
        // Step 2: Decrypt only if authentication passes
        return CFBCipher.decrypt(result.ciphertext, key, result.iv);
    }
}
```

---

## 🎯 Professional Recommendations

### Decision Framework

#### Choose CFB When:
```
✅ Streaming data with unknown/variable length
✅ Real-time processing requirements  
✅ Limited memory environments
✅ Legacy system integration needs
✅ Error recovery capability needed
✅ Simple implementation preferred
```

#### Avoid CFB When:
```
❌ Large bulk data encryption (use CTR/GCM)
❌ Parallel processing requirements
❌ Authentication/integrity critical (use GCM/CCM)
❌ Perfect synchronization not guaranteed
❌ Maximum security required (use AEAD modes)
```

### Best Practices Implementation

```java
public class ProfessionalCFBImplementation {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CFB8/NoPadding";
    private static final int KEY_SIZE = 256; // Use 256-bit for production
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    
    // Production-ready encryption with all safeguards
    public static SecureMessage encrypt(String plaintext, SecretKey key) throws Exception {
        // 1. Input validation
        if (plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty");
        }
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        
        // 2. Generate cryptographically secure IV
        byte[] iv = new byte[16];
        SECURE_RANDOM.nextBytes(iv);
        
        // 3. Encrypt with CFB
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        
        // 4. Generate authentication tag (HMAC)
        byte[] authTag = generateAuthTag(iv, ciphertext, key);
        
        // 5. Return secure container
        return new SecureMessage(iv, ciphertext, authTag);
    }
    
    // Production-ready decryption with verification
    public static String decrypt(SecureMessage message, SecretKey key) throws Exception {
        // 1. Verify authentication tag
        if (!verifyAuthTag(message.iv, message.ciphertext, message.authTag, key)) {
            throw new SecurityException("Message authentication failed - possible tampering");
        }
        
        // 2. Decrypt only after authentication
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(message.iv));
        byte[] decrypted = cipher.doFinal(message.ciphertext);
        
        return new String(decrypted, StandardCharsets.UTF_8);
    }
    
    // Secure container for encrypted messages
    public static class SecureMessage {
        public final byte[] iv;
        public final byte[] ciphertext;
        public final byte[] authTag;
        
        public SecureMessage(byte[] iv, byte[] ciphertext, byte[] authTag) {
            this.iv = iv.clone();
            this.ciphertext = ciphertext.clone();
            this.authTag = authTag.clone();
        }
        
        // Convert to Base64 for storage/transmission
        public String toBase64() {
            return Base64.getEncoder().encodeToString(iv) + ":" +
                   Base64.getEncoder().encodeToString(ciphertext) + ":" +
                   Base64.getEncoder().encodeToString(authTag);
        }
        
        // Reconstruct from Base64
        public static SecureMessage fromBase64(String encoded) {
            String[] parts = encoded.split(":");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid encoded message format");
            }
            
            return new SecureMessage(
                Base64.getDecoder().decode(parts[0]),
                Base64.getDecoder().decode(parts[1]),
                Base64.getDecoder().decode(parts[2])
            );
        }
    }
    
    // HMAC generation for authentication
    private static byte[] generateAuthTag(byte[] iv, byte[] ciphertext, SecretKey key) 
            throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(key);
        hmac.update(iv);
        hmac.update(ciphertext);
        return hmac.doFinal();
    }
    
    // HMAC verification
    private static boolean verifyAuthTag(byte[] iv, byte[] ciphertext, byte[] authTag, SecretKey key) 
            throws Exception {
        byte[] expectedTag = generateAuthTag(iv, ciphertext, key);
        return MessageDigest.isEqual(expectedTag, authTag);
    }
}
```

### Security Checklist for Production

#### ✅ Implementation Checklist:
- [ ] Use AES-256 keys minimum
- [ ] Generate unique IV for every message
- [ ] Implement authentication (HMAC)
- [ ] Validate all inputs
- [ ] Use secure random number generation
- [ ] Handle exceptions securely
- [ ] Clear sensitive data from memory
- [ ] Implement proper key management
- [ ] Add comprehensive logging
- [ ] Perform security testing

#### ✅ Operational Checklist:
- [ ] Secure key storage (HSM/KMS)
- [ ] Regular key rotation
- [ ] Monitor for cryptographic failures
- [ ] Implement replay protection
- [ ] Network security (TLS)
- [ ] Access control and audit logging
- [ ] Disaster recovery procedures
- [ ] Compliance verification

---

## 📚 Conclusion

### CFB Mode Summary

**CFB (Cipher Feedback)** is a **stream cipher mode** that excels in specific scenarios while having notable limitations. Understanding these characteristics is crucial for professional implementation.

#### Key Strengths:
- ✅ **Stream processing**: Ideal for real-time, variable-length data
- ✅ **No padding**: Maintains exact plaintext length
- ✅ **Self-synchronizing**: Recovers from errors automatically
- ✅ **Memory efficient**: Low resource requirements

#### Critical Weaknesses:
- ❌ **Sequential processing**: Cannot parallelize encryption
- ❌ **Error propagation**: Single-bit errors affect multiple bytes
- ❌ **Synchronization dependency**: Requires perfect alignment
- ❌ **No authentication**: Vulnerable to tampering without HMAC

#### Professional Use Cases:
- 🎯 **Ideal**: IoT communications, streaming protocols, real-time encryption
- 🎯 **Avoid**: Bulk data encryption, high-performance scenarios, unauth environments

### Implementation Excellence

For production systems:
1. **Always combine with authentication** (HMAC-SHA256 minimum)
2. **Use 256-bit keys** for future-proofing
3. **Implement proper error handling** and logging
4. **Consider alternatives** (GCM for auth, CTR for performance)
5. **Follow security best practices** throughout the system

### Final Recommendation

**CFB is a valuable tool** in the cryptographic toolkit, but it requires careful consideration of trade-offs. Use it when its strengths align with your requirements, and always implement additional security measures to address its inherent limitations.

---

**📖 References:**
- NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation
- RFC 3711: The Secure Real-time Transport Protocol (SRTP)
- "Cryptography Engineering" by Ferguson, Schneier, and Kohno
- Our practical implementation: [`CFBCipher.java`](CFBCipher.java) and [`CFBDemo.java`](CFBDemo.java)

**🔗 Related Documentation:**
- [`README_CFBCipher.md`](README_CFBCipher.md) - Implementation details
- [`README_CFBDemo.md`](README_CFBDemo.md) - Practical examples
- [`README_Technical.md`](README_Technical.md) - Validation methodology
