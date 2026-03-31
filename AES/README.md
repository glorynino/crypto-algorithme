# AES-128 Cipher Implementation

A clean, educational implementation of the AES-128 (Advanced Encryption Standard) cipher in Python.

## Features

- ✅ Full AES-128 encryption and decryption
- ✅ Proper key expansion (11 round keys)
- ✅ All core AES operations:
  - SubBytes / InvSubBytes
  - ShiftRows / InvShiftRows
  - MixColumns / InvMixColumns
  - AddRoundKey
- ✅ PKCS#7 padding/unpadding
- ✅ ECB mode operation
- ✅ UTF-8 support
- ✅ Comprehensive test suite

## Project Structure

```
AES/
├── utils.py          # Data formatting utilities (padding, conversion)
├── constants.py      # S-Box tables and round constants
├── cipher.py         # Main AES-128 cipher class
├── main.py           # CLI interface
├── tests.py          # Unit tests
└── README.md         # This file
```

## Usage

### As a Module

```python
from cipher import AES128

# Create cipher with 16-byte key
key = b'0123456789abcdef'
cipher = AES128(key)

# Encrypt plaintext (string or bytes)
plaintext = "Hello, World!!!!"
ciphertext = cipher.encrypt(plaintext)

# Decrypt ciphertext
decrypted = cipher.decrypt_text(ciphertext)
print(decrypted)  # "Hello, World!!!!"
```

### CLI Interface

Run the interactive CLI:

```bash
python main.py
```

Menu options:
1. **Encrypt**: Enter a 16-byte key and plaintext to encrypt
2. **Decrypt**: Enter a 16-byte key and hex-encoded ciphertext to decrypt
3. **Exit**: Quit the program

## Running Tests

Execute the test suite:

```bash
python tests.py
```

The test suite includes:
- Key initialization tests
- Single and multi-block encryption/decryption
- Unicode support
- Edge cases (empty strings, exact block sizes)
- Padding/unpadding validation

## Implementation Details

### Key Expansion
- Generates 11 round keys (44 words total) from a 16-byte master key
- Uses SubWord, RotWord, and round constants (R_CON)

### Encryption Round Structure
- **Initial Round**: AddRoundKey only
- **9 Main Rounds**: SubBytes → ShiftRows → MixColumns → AddRoundKey
- **Final Round**: SubBytes → ShiftRows → AddRoundKey (no MixColumns)

### Decryption Round Structure
- **Initial Round**: AddRoundKey only
- **9 Main Rounds**: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
- **Final Round**: InvShiftRows → InvSubBytes → AddRoundKey

### Block Padding
- Uses PKCS#7 padding for messages not aligned to 16-byte blocks
- Padding bytes indicate the number of padding bytes added

## Limitations

⚠️ **This is an educational implementation. For production use, consider:**
- Using established libraries like `cryptography` or `PyCryptodome`
- ECB mode is not secure for real-world use (CBC, GCM, etc. are preferred)
- No timing attack resistance
- No built-in authentication/MAC

## References

- [NIST FIPS 197 - AES Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [Wikipedia - Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
