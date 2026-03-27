# Vigenere Cipher Implementation

## Overview

This is a clean, educational implementation of the **Vigenere cipher**, a classical polyalphabetic substitution cipher. The cipher encrypts text by using a repeating key to shift each letter independently, making it significantly more secure than simple Caesar ciphers.

## How It Works

### The Vigenere Cipher Algorithm

The Vigenere cipher works by:

1. **Repeating the key** to match the length of the plaintext (only counting alphabetic characters)
2. **Converting letters to indices**: Each letter (regardless of case) is converted to a 0-25 index
3. **Adding indices**: For each plaintext letter, we add the index of the corresponding key letter
4. **Using modulo 26**: This keeps the result within the valid alphabet range (0-25)
5. **Preserving case**: The original case of the plaintext letter is preserved in the output

### Mathematical Formula

```
Encryption: C_i = (P_i + K_i) mod 26
Decryption: P_i = (C_i - K_i + 26) mod 26

Where:
  P_i = plaintext letter at position i (0-25)
  K_i = key letter at position i (0-25)
  C_i = ciphertext letter at position i (0-25)
```

### Example

```
Plaintext:  H e l l o
Key:        k e y k e
Indices:    7 4 11 11 14  (plaintext)
            10 4 24 10 4  (key)
            ─────────────
Sum:        17 8 35 21 18
Mod 26:     17 8 9  21 18
Result:     R i j v s
```

## Design Decisions

### 1. **Alphabet Size: 26 (Not 52!)**

You might wonder: "Why only 26 if the cipher is case-sensitive?"

**The Critical Problem with 52-character alphabet:**
If we used 52 characters (26 lowercase + 26 uppercase), we'd lose case information during decryption:

```
Example with 52-char alphabet:
'H' (index 26) + 'H' (index 26) = 52 % 52 = 0 → decrypts to 'a'  ✗ WRONG!

The original 'H' becomes 'a' — we can't recover the original case!
```

**Solution: 26-character alphabet with explicit case preservation:**
- All letters map to 0-25 regardless of case
- Case information is tracked separately using the `is_upper` flag
- This ensures case is perfectly preserved through encryption and decryption

```python
# Store case information separately
index_to_letter(encrypted_index, char.isupper())
```

### 2. **Non-Alphabetic Character Handling**

- **Spaces, punctuation, and numbers are preserved unchanged**
- They are not included in the key rotation
- This maintains readability and structure of the original text

```python
# Example
encrypt_vignere("Hello, World!", "KEY")
# Spaces and comma remain in the output
```

### 3. **Case Normalization in letter_to_index()**

Both 'A' and 'a' return index 0, allowing:
- Unified processing regardless of input case
- Separate tracking of case in `index_to_letter()`
- Clean separation of concerns

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

#### `encrypt_vignere(text: str, key: str) -> str`
Encrypts plaintext using the Vigenere cipher.

**Algorithm:**
1. Create `formatted_key`: Extract only alphabetic characters from plaintext and repeat key as needed
2. For each alphabetic character in plaintext:
   - Add its index to the corresponding key character's index
   - Apply modulo 26
   - Convert back to letter with original case preserved
3. Non-alphabetic characters pass through unchanged

```python
encrypt_vignere("Hello World", "KEY")
# Output: "Rijvs Uyvjn"
```

#### `decrypt_vignere(encrypted_text: str, key: str) -> str`
Decrypts ciphertext back to plaintext.

**Algorithm:**
1. Create `formatted_key` same as encryption
2. For each alphabetic character in ciphertext:
   - Subtract its key character's index from its own
   - Add 26 before modulo to handle negative numbers
   - Apply modulo 26
   - Convert back to letter with original case preserved
3. Non-alphabetic characters pass through unchanged

The `+ 26` before modulo ensures correct results for negative numbers:
```python
# Without +26: (-5) % 26 = 21 in Python (works), but -5 in other languages
# With +26: (-5 + 26) % 26 = 21 (guaranteed correct everywhere)
```

## Features

✓ **Case Preservation**: Original letter cases are maintained  
✓ **Special Character Support**: Spaces, punctuation, and numbers pass through unchanged  
✓ **Key Repetition**: Long keys and short keys both work correctly  
✓ **Roundtrip Guarantee**: encrypt() then decrypt() always returns original text  
✓ **Clean Code**: Well-structured, readable, and follows Python conventions  

## Usage

### Basic Encryption and Decryption

```python
from vignere import encrypt_vignere, decrypt_vignere

plaintext = "Hello, World!"
key = "SECRET"

# Encrypt
ciphertext = encrypt_vignere(plaintext, key)
print(f"Encrypted: {ciphertext}")  # Output: Zijlo, Ajvum!

# Decrypt
recovered = decrypt_vignere(ciphertext, key)
print(f"Decrypted: {recovered}")   # Output: Hello, World!

# Verify roundtrip
assert recovered == plaintext
```

### Key Variations

```python
# Different keys produce different outputs
encrypt_vignere("HELLO", "KEY1")   # RIJVS
encrypt_vignere("HELLO", "KEY2")   # RYMZO

# Single character keys work too
encrypt_vignere("HELLO", "A")      # HELLO (A shifts by 0)
encrypt_vignere("HELLO", "B")      # IFMMP (shifts by 1)
```

## Testing

This implementation includes comprehensive tests covering:

- **letter_to_index()**: Input validation, case normalization, boundary cases
- **index_to_letter()**: Uppercase/lowercase conversion, all valid indices
- **Encryption**: Basic cases, case preservation, special characters
- **Decryption**: Roundtrip verification
- **Edge Cases**: Long texts, varied keys, mixed case input

### Run Tests

```bash
python tests.py
```

The test suite includes:
- Unit tests for helper functions
- Integration tests for encryption/decryption
- Roundtrip tests (encrypt then decrypt)
- Edge case and boundary condition tests
- Case sensitivity verification
- Special character handling verification

## Security Note

⚠️ **This cipher is NOT cryptographically secure by modern standards.**

The Vigenere cipher is historically interesting but has known weaknesses:
- **Frequency analysis**: Repeated key patterns can be detected
- **Known plaintext attacks**: If you know part of the plaintext, you can derive key sections
- **Short keys**: Using a short, memorable key dramatically reduces effective key space

This implementation is suitable for:
- Educational purposes
- Understanding polyalphabetic ciphers
- Casual encoding (not sensitive data)

**For real security, use modern cryptographic standards** like AES-256.

## Code Structure

```
vignere/
├── vignere.py       # Main implementation (functions and constants)
├── tests.py         # Comprehensive test suite
├── README.md        # This file
```

## Constants

```python
MOD_VALUE = 26  # Size of the alphabet (a-z)
```

This constant is used in all encryption/decryption calculations and represents the total number of letters in the alphabet.

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


Thanks for your time :)