# TP 1 - COMPLETION SUMMARY

## ✅ All Exercises Completed

### Exercise 1.1 - César Cipher
**Status: COMPLETE**

**Implementations:**
- [Caesar cipher/caesar.py](Caesar%20cipher/caesar.py) - Basic encryption/decryption
- [Caesar cipher/caesar_attacks.py](Caesar%20cipher/caesar_attacks.py) - 3 attack methods

**Attacks Implemented:**
1. ✅ **Brute Force (Dictionary-based)**
   - Tests all 26 possible shifts
   - Scores by French word recognition
   - Best for short ciphertexts with common words

2. ✅ **Frequency Analysis (Index of Coincidence)**
   - Calculates IC for each shift
   - IC(French) ≈ 0.074
   - Finds shift closest to French IC

3. ✅ **Chi-Squared Test**
   - Compares observed vs. expected letter frequency
   - Most reliable for longer texts
   - **Successfully verified** in test

---

### Exercise 1.2 - Vigenère Cipher
**Status: COMPLETE**

**Implementations:**
- [Vignere cipher/vignere.py](Vignere%20cipher/vignere.py) - Basic encryption/decryption
- [Vignere cipher/vignere_attacks.py](Vignere%20cipher/vignere_attacks.py) - 3 attack methods

**Attacks Implemented:**
1. ✅ **Kasiski Examination (Trigramme Analysis)**
   - Finds repeated patterns in ciphertext
   - Calculates distances between repetitions
   - GCD of distances gives key length estimate

2. ✅ **Index of Coincidence (IC) Analysis**
   - Tests each possible key length 1-20
   - Calculates average IC of k subsequences
   - Best IC ≈ 0.074 indicates correct length

3. ✅ **Key Recovery via Frequency Analysis**
   - Once key length known, splits ciphertext into k subsequences
   - Each subsequence = Caesar cipher with different shift
   - Applies chi-squared frequency analysis to recover each key letter

---

### Exercise 1.3 - Hill Cipher
**Status: COMPLETE**

**Implementations:**
- [HILL/hill.py](HILL/hill.py) - Encryption/decryption for 2×2 and 3×3 matrices
- [HILL/hill_attacks.py](HILL/hill_attacks.py) - Known-plaintext attack

**Attacks Implemented:**
1. ✅ **Known-Plaintext Attack (2×2)**
   - Given: plaintext and corresponding ciphertext
   - Recovers key matrix K = C × P⁻¹ (mod 26)
   - **Verified**: Successfully recovers key and decrypts

2. ✅ **Known-Plaintext Attack (3×3)**
   - Same principle with 3×3 matrices
   - Requires inverting 3×3 matrix mod 26
   - **Verified**: Works correctly

3. ✅ **Security Analysis**
   - Shows why Hill is vulnerable to linear algebra attacks
   - Demonstrates that large matrices don't help (still linear)

---

### Exercise 1.4 - One-Time Pad (OTP/Vernam)
**Status: COMPLETE**

**Implementations:**
- [OTP algorithm/otp.py](OTP%20algorithm/otp.py) - Basic OTP encryption/decryption
- [OTP algorithm/otp_attacks.py](OTP%20algorithm/otp_attacks.py) - Vulnerability demonstrations

**Attacks Implemented:**
1. ✅ **Key Reuse Vulnerability**
   - Encrypts two messages with same key
   - Shows: C₁ ⊕ C₂ = M₁ ⊕ M₂ (key cancels out!)
   - **Verified**: Demonstrates information leakage

2. ✅ **Crib Dragging**
   - Attacker suspects known plaintext (e.g., "THE")
   - Tests position by calculating: M₂ = "THE" ⊕ (C₁ ⊕ C₂)
   - Checks if result is valid text
   - **Demonstrated**: Recovers partial messages

3. ✅ **Statistical Analysis**
   - Entropy analysis on XOR results
   - Shows structural patterns emerge from M₁ ⊕ M₂
   - Security implications discussed

---

## Test Results

### Quick Test (Caesar)
```
✓ Original (length 54):  BONJOURCOMMENTCAVAAUJOURDHUILEMONDEESTMAGNIFIQUEET...
✓ Shift: 7
✓ Encrypted: IVUQVBYJVTTLUAJHCHHBQVBYKOBPSLTVUKLLZATHNUPMPXBLLA...

CHI-SQUARED FREQUENCY ANALYSIS
1. Shift 7: χ² = 31.14 ✓ CORRECT!
2. Shift 19: χ² = 143.49
3. Shift 18: χ² = 281.53
```

---

## File Structure

```
/home/matt-anis/Studies/Crypto/
├── Caesar cipher/
│   ├── caesar.py              ✅ COMPLETE
│   ├── caesar_attacks.py      ✅ COMPLETE
│   └── tests.py
│
├── Vignere cipher/
│   ├── vignere.py             ✅ COMPLETE
│   ├── vignere_attacks.py     ✅ COMPLETE
│   └── tests.py
│
├── HILL/
│   ├── hill.py                ✅ COMPLETE
│   ├── hill_attacks.py        ✅ COMPLETE
│   └── tests.py
│
├── OTP algorithm/
│   ├── otp.py                 ✅ COMPLETE
│   ├── otp_attacks.py         ✅ COMPLETE
│   └── tests.py
│
├── tp1_complete.py            ✅ NEW - Comprehensive test suite
├── test_tp1_quick.py          ✅ NEW - Quick validation test
├── TP1_README.md              ✅ NEW - Full documentation
└── TP1_SUMMARY.md             ✅ NEW - This file
```

---

## How to Run

### Run All TP1 Tests
```bash
cd /home/matt-anis/Studies/Crypto
source .venv/bin/activate
python3 tp1_complete.py     # Full detailed output
```

### Run Quick Caesar Test
```bash
python3 test_tp1_quick.py
```

### Run Individual Exercise Tests
```bash
cd "Caesar cipher" && python3 tests.py
cd "../Vignere cipher" && python3 tests.py
cd ../HILL && python3 tests.py
cd "../OTP algorithm" && python3 tests.py
```

### Run Individual Attack Demonstrations
```bash
cd "Caesar cipher"
python3 caesar_attacks.py       # Shows all 3 Caesar attacks

cd ../Vignere\ cipher
python3 vignere_attacks.py      # Shows Kasiski + IC + key recovery

cd ../HILL
python3 hill_attacks.py         # Shows known-plaintext attack

cd ../OTP\ algorithm
python3 otp_attacks.py          # Shows key reuse + crib dragging
```

---

## Key Insights Demonstrated

### 1. Classical Ciphers are Insecure
- All classical encryption can be broken with statistical analysis
- Even "sophisticated" ciphers (Vigenère, Hill) are vulnerable

### 2. Frequency Analysis is Powerful
- IC reveals the language even when text is encrypted
- Character distribution patterns are preserved through substitution

### 3. Repetition Enables Attacks
- Vigenère: Key repeats → Kasiski finds length
- OTP: Key reused → M₁ ⊕ M₂ leaks structure

### 4. Linearity is Weakness
- Hill cipher's linear mathematics makes it vulnerable
- Known-plaintext fully recovers the key

### 5. OTP is Theoretically Perfect But Impractical
- Requires true randomness, secure key distribution, **zero reuse**
- One mistake (key reuse) = total compromise

---

## Comparison: Vulnerabilities

| Cipher | Attack | Data Needed | Complexity | Probability |
|--------|--------|-------------|-----------|------------|
| **César** | Brute Force | Ciphertext | O(26) | 100% |
| ^| Frequency Analysis | 50+ chars | O(26×n) | 95%+ |
| **Vigenère** | Kasiski | 100+ chars | O(k²) | 80%+ |
| ^| IC Analysis | 500+ chars | O(k×26) | 90%+ |
| ^| Full Recovery | 1000+ chars | O(k×26×n) | 99%+ |
| **Hill** | Known-Plaintext | 2 blocks | O(k³) | 100% |
| ^| Ciphertext-Only | ∞ chars | ??? | 0% (?) |
| **OTP** | Key Reuse | 2 messages | O(min(M₁,M₂)) | 100% |
| ^| Single Use | Any | ∞ | 0% (perfect) |

---

## Dependencies

```
✅ sympy       - Used in Hill cipher for matrix operations
✅ cryptography - (optional, for future TPs)
✅ pycryptodome - (optional, for future TPs)
```

All dependencies installed in `.venv/`

---

## Next Steps: TP 2

**Cryptographie Symétrique Moderne**
- RC4 (stream cipher)
- DES + 3DES (block cipher)
- AES (Rijndael) + 5 NIST finalists
- Modes: ECB, CBC, CTR
- Vulnerabilities and attacks

---

**TP 1 Status: ✅ FULLY COMPLETE**

Final update: May 11, 2026
