"""Simple tests for Vigenere cipher."""

from vignere import letter_to_index, index_to_letter, encrypt_vignere, decrypt_vignere

# Test 1: letter_to_index
print("Test 1: letter_to_index")
assert letter_to_index('a') == 0, "lowercase 'a' should be 0"
assert letter_to_index('z') == 25, "lowercase 'z' should be 25"
assert letter_to_index('A') == 0, "uppercase 'A' should be 0"
assert letter_to_index('Z') == 25, "uppercase 'Z' should be 25"
print("✓ letter_to_index works correctly\n")

# Test 2: index_to_letter
print("Test 2: index_to_letter")
assert index_to_letter(0, False) == 'a', "index 0 should be lowercase 'a'"
assert index_to_letter(25, False) == 'z', "index 25 should be lowercase 'z'"
assert index_to_letter(0, True) == 'A', "index 0 with is_upper=True should be 'A'"
assert index_to_letter(25, True) == 'Z', "index 25 with is_upper=True should be 'Z'"
print("✓ index_to_letter works correctly\n")

# Test 3: Basic encryption
print("Test 3: Basic encryption")
encrypted = encrypt_vignere('Hello', 'key')
assert isinstance(encrypted, str), "encryption should return a string"
assert len(encrypted) == 5, "encrypted text should have same length as plaintext"
print(f"'Hello' encrypted with key 'key': {encrypted}")
print("✓ Encryption works\n")

# Test 4: Basic decryption
print("Test 4: Basic decryption")
plaintext = "Hello World"
key = "secret"
encrypted = encrypt_vignere(plaintext, key)
decrypted = decrypt_vignere(encrypted, key)
assert decrypted == plaintext, f"decrypted text should be '{plaintext}' but got '{decrypted}'"
print(f"Original:  {plaintext}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")
print("✓ Decryption works\n")

# Test 5: Case preservation
print("Test 5: Case preservation")
plaintext = "HeLLo WoRLD"
encrypted = encrypt_vignere(plaintext, "key")
assert encrypted[0].isupper(), "First letter should stay uppercase"
assert encrypted[2].isupper(), "Third letter should stay uppercase"
assert encrypted[1].islower(), "Second letter should stay lowercase"
print(f"Original:  {plaintext}")
print(f"Encrypted: {encrypted}")
print("✓ Case is preserved\n")

# Test 6: Non-alphabetic characters
print("Test 6: Non-alphabetic characters")
plaintext = "Hello123World!"
encrypted = encrypt_vignere(plaintext, "key")
decrypted = decrypt_vignere(encrypted, "key")
assert decrypted == plaintext, f"Non-alphabetic chars should be preserved"
print(f"Original:  {plaintext}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")
print("✓ Non-alphabetic characters are preserved\n")

print("="*50)
print("All tests passed! ✓")
print("="*50)
