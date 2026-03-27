# Caesar Cipher Implementation

## Overview

This is a clean, educational implementation of the **Caesar cipher**, a classical substitution cipher where each letter is shifted by a fixed number of positions in the alphabet. It's one of the simplest and most well-known encryption techniques in cryptography.

## How It Works

### The Caesar Cipher Algorithm

The Caesar cipher works by:

1. **Choosing a shift value**: A fixed number (typically 3, but can be any value 0-25)
2. **Converting letters to indices**: Each letter (regardless of case) is converted to a 0-25 index
3. **Shifting the index**: Add the shift value to the index
4. **Using modulo 26**: This keeps the result within the valid alphabet range (0-25)
5. **Preserving case**: The original case of the plaintext letter is preserved in the output

### Mathematical Formula

```
Encryption: C_i = (P_i + S) mod 26
Decryption: P_i = (C_i - S + 26) mod 26

Where:
  P_i = plaintext letter at position i (0-25)
  S = shift value (0-25)
  C_i = ciphertext letter at position i (0-25)
```

### Example

```
Plaintext:  H e l l o
Shift:      3 3 3 3 3
Indices:    7 4 11 11 14  (plaintext)
            ─────────────
Add Shift:  10 7 14 14 17
Result:     K h o o r
```

## Design Decisions

### 1. **Fixed Shift with Encryption/Decryption Functions**

The implementation provides two complementary functions:
- `caesar_cipher(text, shift)`: Encrypts by shifting forward
- `caesar_decipher(text, shift)`: Decrypts by shifting backward (equivalent to `caesar_cipher(text, -shift)`)

This design:
- Allows encoding and decoding with the same interface
- Is symmetric and intuitive
- Works with both positive and negative shift values

```python
# Encrypt with shift +3
encrypt = caesar_cipher("Hello", 3)      # "Khoor"

# Decrypt with shift +3 (equivalent to -3)
decrypt = caesar_decipher("Khoor", 3)    # "Hello"
```

### 2. **Case Preservation**

- Both uppercase and lowercase letters are handled correctly
- Case information is tracked using the `is_upper` flag
- The original case of each letter is preserved in the output

```python
caesar_cipher("HeLLo", 1)  # "IfMMP" - case preserved
```

### 3. **Non-Alphabetic Character Handling**

- **Spaces, punctuation, and numbers are preserved unchanged**
- They are not shifted
- This maintains readability and structure of the original text

```python
caesar_cipher("Hello, World!", 3)  # "Khoor, Zruog!" - punctuation unchanged
```

## Implementation Details

### Core Functions

#### `letter_to_index(letter: str) -> int`
Converts a single letter to its index (0-25).
- Input case is normalized to uppercase
- Raises `ValueError` for non-alphabetic characters
- Returns 0-25 regardless of input case

```python
letter_to_index('A')  # Returns 0
letter_to_index('a')  # Returns 0
letter_to_index('Z')  # Returns 25
```

#### `index_to_letter(index: int, is_upper: bool) -> str`
Converts an index back to a letter, respecting the case flag.
- `is_upper=True` returns uppercase letter
- `is_upper=False` returns lowercase letter
- Requires index to be in range 0-25

```python
index_to_letter(0, True)   # Returns 'A'
index_to_letter(0, False)  # Returns 'a'
index_to_letter(25, True)  # Returns 'Z'
```

#### `caesar_cipher(text: str, shift: int) -> str`
Encrypts plaintext using the Caesar cipher with a given shift.

**Algorithm:**
1. For each alphabetic character in plaintext:
   - Convert to index
   - Add the shift value
   - Apply modulo 26 to wrap around the alphabet
   - Convert back to letter with original case preserved
2. Non-alphabetic characters pass through unchanged

```python
caesar_cipher("Hello World", 3)     # Output: "Khoor Zruog"
caesar_cipher("Hello World", 13)    # Output: "Uryyb Jbeyq" (ROT13)
caesar_cipher("Hello World", 25)    # Output: "Gdkkn Vnqkc" (shift backward by 1)
```

#### `caesar_decipher(text: str, shift: int) -> str`
Decrypts ciphertext back to plaintext.

**Implementation:**
```python
def caesar_decipher(text, shift):
    return caesar_cipher(text, -shift)
```

This simply shifts in the opposite direction. The `+ 26` in the modulo operation within `caesar_cipher` ensures correct results for negative shifts:

```python
# Example: Decrypting 'K' with shift +3
# (10 + (-3)) % 26 = 7 % 26 = 7 → 'H' ✓
```

## Features

✓ **Simplicity**: The classic Caesar cipher, easy to understand  
✓ **Case Preservation**: Original letter cases are maintained  
✓ **Special Character Support**: Spaces, punctuation, and numbers pass through unchanged  
✓ **Bidirectional**: Same function works for encryption with positive shifts and decryption with negative shifts  
✓ **Roundtrip Guarantee**: encrypt() then decrypt() always returns original text  
✓ **Clean Code**: Well-structured, readable, and follows Python conventions  

## Usage

### Basic Encryption and Decryption

```python
from caesar import caesar_cipher, caesar_decipher

plaintext = "Hello, World!"

# Encrypt with shift +3
ciphertext = caesar_cipher(plaintext, 3)
print(f"Encrypted: {ciphertext}")  # Output: Khoor, Zruog!

# Decrypt with shift +3 (shifts backward by 3)
recovered = caesar_decipher(ciphertext, 3)
print(f"Decrypted: {recovered}")   # Output: Hello, World!

# Verify roundtrip
assert recovered == plaintext
```

### Different Shift Values

```python
# Classic Caesar shift of 3
caesar_cipher("HELLO", 3)    # KHOOR

# ROT13 (shift of 13, often used for obfuscation)
caesar_cipher("HELLO", 13)   # URYYB

# Shift by 1
caesar_cipher("HELLO", 1)    # IFMMP

# Shift backward (wrap around)
caesar_cipher("HELLO", 25)   # GDKKN (equivalent to shift -1)
```

### Brute Force Attack Example

```python
# The Caesar cipher has only 26 possible shifts, so brute force is trivial:
ciphertext = "KHOOR"
for shift in range(26):
    print(f"Shift {shift}: {caesar_decipher(ciphertext, shift)}")
# One of the outputs will be the original text
```

## Testing

This implementation includes comprehensive tests covering:

- **letter_to_index()**: Case normalization, boundary cases
- **index_to_letter()**: Uppercase/lowercase conversion, all valid indices
- **Encryption**: Basic cases, case preservation, special characters
- **Decryption**: Roundtrip verification
- **Edge Cases**: Various shift values

### Run Tests

```bash
python tests.py
```

The test suite includes:
- Unit tests for helper functions
- Integration tests for encryption/decryption
- Roundtrip tests (encrypt then decrypt)
- Case sensitivity verification
- Special character handling verification

## Security Note

⚠️ **This cipher is NOT secure by any modern standard.**

The Caesar cipher has critical weaknesses:
- **Only 26 possible shifts**: If you know it's a Caesar cipher, brute force takes seconds
- **Frequency analysis**: Common letters like 'E' remain frequent in the ciphertext
- **No key**: The "key" is just the shift value, easily guessed or brute forced
- **Deterministic**: Same plaintext always produces same ciphertext

The Caesar cipher is useful for:
- Educational purposes
- Understanding basic cryptographic principles
- Simple text obfuscation (not security)

**For real security, use modern cryptographic standards** like AES-256.

## Code Structure

```
Caesar cipher/
├── caesar.py       # Main implementation (functions and constants)
├── tests.py        # Comprehensive test suite
├── README.md       # This file
```

## Constants

```python
MOD_VALUE = 26  # Size of the alphabet (a-z)
```

This constant represents the total number of letters in the alphabet and is used in all encryption/decryption calculations.

## Error Handling

The implementation includes input validation:

```python
# Invalid input to letter_to_index
letter_to_index("12")    # ValueError: "12" is not a letter!
letter_to_index("@")     # ValueError: @ is not a letter!

# Invalid input to index_to_letter
index_to_letter(26, True)  # ValueError: 26 is not a valid index!
index_to_letter(-1, False) # ValueError: -1 is not a valid index!
```

---

Thanks for your time! Happy ciphering! 🔐
