# TP 4 - Cryptographic Hash Functions

## Overview

This TP covers cryptographic hash function theory and practice:
- **MD5**: Message Digest 5 (128-bit, **BROKEN**)
- **SHA-256**: Secure Hash Algorithm 256-bit (256-bit, recommended)
- **SHA-512**: Secure Hash Algorithm 512-bit (512-bit, recommended)
- **HMAC**: Hash-based Message Authentication Code

## Exercises

### Exercise 4.1 - MD5 (Message Digest 5)

**Objective**: Understand why MD5 is broken and should not be used for security.

**Implementations**:
- [MD5/md5.py](../MD5/md5.py) - Pure Python MD5 implementation

**Tasks**:
1. ✅ Calculate MD5 hashes of various inputs (empty, 1 byte, 1 KB, 1 MB, binary)
2. ✅ Verify output is always 128 bits (16 bytes)
3. ✅ Test avalanche effect - 1-bit change should flip ~50% of output bits
4. ✅ Demonstrate collision resistance failure

**Key Findings**:
- MD5 produces 128-bit (16-byte) hashes
- Good avalanche effect observed
- **Status**: BROKEN - practical collisions found in 2004
- **Recommendation**: Use SHA-256 or SHA-512 instead

---

### Exercise 4.2 - SHA-256 (Secure Hash Algorithm 2)

**Objective**: Implement and validate SHA-256, the most widely-used secure hash.

**Implementations**:
- [SHA/sha256.py](../SHA/sha256.py) - Complete SHA-256 from scratch

**Tasks**:
1. ✅ Implement SHA-256 from first principles:
   - Padding (Merkle-Damgård)
   - Message schedule expansion
   - 64 compression rounds with 64 constants
   - Validate against test vectors

2. ✅ File integrity verification:
   - Compute file hashes
   - Detect modifications
   - Practical use case: Linux ISO verification

3. ✅ HMAC operations:
   - Authenticated hashing
   - Message authentication code

**Key Findings**:
- SHA-256 produces 256-bit (32-byte) hashes
- Excellent avalanche effect
- **Status**: STRONG - no collisions known
- **Uses**: TLS, Git, Bitcoin, JWT, code signing

---

### Exercise 4.3 - Comparison & Performance

**Objective**: Compare hash functions and analyze performance trade-offs.

**Implementations**:
- [Hash/hash_analysis.py](../Hash/hash_analysis.py) - Comparative analysis
- [Hash/file_integrity.py](../Hash/file_integrity.py) - File verification

**Tasks**:
1. ✅ Algorithm comparison table (output size, speed, security)
2. ✅ Performance benchmark on 100 MB data:
   - Measure throughput (MB/s)
   - Identify fastest/slowest
   - Performance impact of key length

3. ✅ Statistical analysis:
   - Check bit distribution in outputs
   - Verify avalanche effect for all algorithms
   - Confirm ~50% bit flip on 1-bit input change

**Comparison Matrix**:

| Algorithm | Bits | Recommended | Status | Use Case |
|-----------|------|-------------|--------|----------|
| **MD5** | 128 | ✗ No | BROKEN | Legacy only |
| **SHA-256** | 256 | ✓ Yes | STRONG | TLS, Bitcoin |
| **SHA-512** | 512 | ✓ Yes | STRONG | Signatures |
| **SHA-3** | 256/512 | ✓ Yes | STRONG | Modern |

---

## Files Structure

```
├── tp4_complete.py          # Main test suite
├── MD5/
│   └── md5.py               # MD5 implementation (educational)
├── SHA/
│   └── sha256.py            # SHA-256 implementation
├── Hash/
│   ├── hash_analysis.py     # Comparative analysis
│   └── file_integrity.py    # File verification
└── TP4_SUMMARY.md          # This file
```

## Running the Tests

```bash
# Full TP4 test suite
python3 tp4_complete.py

# Individual tests
python3 MD5/md5.py          # MD5 validation
python3 SHA/sha256.py       # SHA-256 validation
python3 Hash/hash_analysis.py       # Analysis tools
python3 Hash/file_integrity.py      # File integrity demo
```

## Security Implications

### MD5 - ✗ BROKEN
- **Collisions Found**: 2004 (Wang & Yu, freely computable)
- **Status**: Do NOT use for security
- **Legacy Use**: Checksums, non-security contexts only
- **Recommendation**: Replace with SHA-256

### SHA-256 - ✓ STRONG
- **Security Level**: 128 bits (quantum-resistant to 2^128)
- **Collisions**: None known
- **Status**: Industry standard
- **Recommendation**: Use for most applications

### SHA-512 - ✓ STRONG
- **Security Level**: 256 bits (quantum-resistant to 2^256)
- **Performance**: Faster than SHA-256 on 64-bit CPUs
- **Status**: Industry standard
- **Recommendation**: Use for high-security applications

## Birthday Paradox Analysis

For a hash function with **n-bit output**, approximately **2^(n/2)** random inputs are needed before expecting one collision:

- **MD5** (128-bit): ~2^64 messages (infeasible) → **Already broken**
- **SHA-256** (256-bit): ~2^128 messages (infeasible) ✓
- **SHA-512** (512-bit): ~2^256 messages (infeasible) ✓

## Avalanche Effect

Perfect cryptographic hash must show **avalanche effect**:
- 1-bit change in input → ~50% of output bits change
- This was verified for all three algorithms

## Modern Recommendations (2026)

**For new projects**:
- ✓ Use **SHA-256** or **SHA-512** (Merkle-Damgård)
- ✓ Consider **SHA-3 (Keccak)** for cutting-edge security
- ✗ Never use **MD5** for security
- ✗ Never use **SHA-1** (deprecated, collisions found)

**For HMAC authentication**:
- Use `HMAC-SHA256` with strong secret keys
- Example: JWT tokens, API authentication

## References

- NIST FIPS 180-4: SHA Hash Function Standards
- SHA-256 Correctness: Validated against test vectors
- Collision resistance: Birthday paradox principle
- Avalanche effect: Critical for cryptographic security

---

## ✓ Completion Status

- ✅ Exercise 4.1: MD5 analysis
- ✅ Exercise 4.2: SHA-256 implementation  
- ✅ Exercise 4.3: Comparison & performance
- ✅ Avalanche effect demonstration
- ✅ File integrity verification
- ✅ HMAC authentication
- ✅ Security analysis and recommendations
