"""Small DES-CBC helper built on PyCryptodome."""

from __future__ import annotations

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def _coerce_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode()
    return bytes(value)


def chiffrement_cbc(texte_clair, cle):
    key = _coerce_bytes(cle)
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes.")

    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    plaintext = _coerce_bytes(texte_clair)
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
    return (iv + ciphertext).hex().upper()


def dechiffrement_cbc(texte_chiffre, cle):
    key = _coerce_bytes(cle)
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes.")

    data = bytes.fromhex(texte_chiffre) if isinstance(texte_chiffre, str) else _coerce_bytes(texte_chiffre)
    if len(data) < 16 or len(data) % 8 != 0:
        raise ValueError("Ciphertext must include an IV and full DES blocks.")

    iv, ciphertext = data[:8], data[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return plaintext.decode()


def __main__():
    print("===================================== Methode de chiffrement CBC ================================")
    key = get_random_bytes(8)
    message = input("Entrez le texte a chiffrer: ")
    encrypted = chiffrement_cbc(message, key)
    print("Texte chiffre:", encrypted)
    print("Texte dechiffre:", dechiffrement_cbc(encrypted, key))


if __name__ == "__main__":
    __main__()