from rc4 import encryption, decryption
def test_rc4():
    key = "glory"
    message = "hello world"

    encrypted = encryption(key, message)
    decrypted = decryption(key, encrypted)

    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)

    assert decrypted == message

if __name__ == "__main__":
    test_rc4()
    print("Test reussi !")