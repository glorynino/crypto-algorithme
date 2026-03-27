"""Simple tests for Caesar cipher."""

from caesar import letter_to_index, index_to_letter, caesar_cipher, caesar_decipher

# Test 1: letter_to_index
print("Test 1: letter_to_index")
assert letter_to_index('a') == 0, "lowercase 'a' should be 0"
assert letter_to_index('z') == 25, "lowercase 'z' should be 25"
assert letter_to_index('A') == 0, "uppercase 'A' should be 0"
assert letter_to_index('Z') == 25, "uppercase 'Z' should be 25"
assert letter_to_index('m') == 12, "lowercase 'm' should be 12"
print("✓ letter_to_index works correctly\n")

# Test 2: index_to_letter
print("Test 2: index_to_letter")
assert index_to_letter(0, False) == 'a', "index 0 should be lowercase 'a'"
assert index_to_letter(25, False) == 'z', "index 25 should be lowercase 'z'"
assert index_to_letter(0, True) == 'A', "index 0 with is_upper=True should be 'A'"
assert index_to_letter(25, True) == 'Z', "index 25 with is_upper=True should be 'Z'"
assert index_to_letter(12, True) == 'M', "index 12 with is_upper=True should be 'M'"
print("✓ index_to_letter works correctly\n")

# Test 3: Basic encryption
print("Test 3: Basic encryption")
encrypted = caesar_cipher('Hello', 3)
assert isinstance(encrypted, str), "encryption should return a string"
assert len(encrypted) == 5, "encrypted text should have same length as plaintext"
assert encrypted == 'Khoor', f"'Hello' shifted by 3 should be 'Khoor' but got '{encrypted}'"
print(f"'Hello' encrypted with shift 3: {encrypted}")
print("✓ Encryption works\n")

# Test 4: Basic decryption
print("Test 4: Basic decryption")
plaintext = "Hello World"
shift = 5
encrypted = caesar_cipher(plaintext, shift)
decrypted = caesar_decipher(encrypted, shift)
assert decrypted == plaintext, f"decrypted text should be '{plaintext}' but got '{decrypted}'"
print(f"Original:  {plaintext}")
print(f"Encrypted (shift +{shift}): {encrypted}")
print(f"Decrypted: {decrypted}")
print("✓ Decryption works\n")

# Test 5: Case preservation
print("Test 5: Case preservation")
plaintext = "HeLLo WoRLD"
encrypted = caesar_cipher(plaintext, 3)
assert encrypted[0].isupper(), "First letter should stay uppercase"
assert encrypted[2].isupper(), "Third letter should stay uppercase"
assert encrypted[1].islower(), "Second letter should stay lowercase"
print(f"Original:  {plaintext}")
print(f"Encrypted: {encrypted}")
print("✓ Case is preserved\n")

# Test 6: Non-alphabetic characters
print("Test 6: Non-alphabetic characters")
plaintext = "Hello123World!"
shift = 7
encrypted = caesar_cipher(plaintext, shift)
decrypted = caesar_decipher(encrypted, shift)
assert decrypted == plaintext, f"Non-alphabetic chars should be preserved"
# Check that numbers and punctuation are unchanged
assert '1' in encrypted and '2' in encrypted and '3' in encrypted, "Numbers should be preserved"
assert '!' in encrypted, "Punctuation should be preserved"
print(f"Original:  {plaintext}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")
print("✓ Non-alphabetic characters are preserved\n")

# Test 7: ROT13 (shift 13)
print("Test 7: ROT13 (shift 13)")
plaintext = "HELLO"
encrypted = caesar_cipher(plaintext, 13)
# ROT13 is self-inverse: applying it twice returns the original
double_encrypted = caesar_cipher(encrypted, 13)
assert double_encrypted == plaintext, "ROT13 applied twice should return original"
print(f"Original:   {plaintext}")
print(f"ROT13:      {encrypted}")
print(f"ROT13 again: {double_encrypted}")
print("✓ ROT13 works correctly\n")

# Test 8: Wrap-around at end of alphabet
print("Test 8: Wrap-around at end of alphabet")
encrypted = caesar_cipher("XYZ", 3)
assert encrypted == "ABC", f"'XYZ' shifted by 3 should wrap to 'ABC' but got '{encrypted}'"
print(f"'XYZ' encrypted with shift 3: {encrypted}")
print("✓ Wrap-around works correctly\n")

# Test 9: Negative shift (backward shift)
print("Test 9: Negative shift (backward shift)")
plaintext = "HELLO"
encrypted_forward = caesar_cipher(plaintext, 3)
encrypted_backward = caesar_cipher(plaintext, -3)
# Shifting forward by 3 then backward by 3 should give original
recovered = caesar_cipher(encrypted_forward, -3)
assert recovered == plaintext, "Shifting forward then backward should return original"
print(f"Original:        {plaintext}")
print(f"Shift +3:        {encrypted_forward}")
print(f"Shift -3:        {encrypted_backward}")
print(f"Recover (+3,-3): {recovered}")
print("✓ Negative shifts work correctly\n")

print("="*50)
print("All tests passed! ✓")
print("="*50)
