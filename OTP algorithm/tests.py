from otp import encryption, decryption
#ici on test si mon fichier de otp fonctionne correctement
# Test decryption
ciphertext, key = encryption("Hello world")
assert decryption(ciphertext, key) == "Hello world"
print("decryption OK ")

# Test encryption
assert len(ciphertext) == len("Hello world")
print("encryption OK ")