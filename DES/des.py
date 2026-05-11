"""DES and Triple-DES helpers backed by PyCryptodome."""

from __future__ import annotations

from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad


def _coerce_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode()
    return bytes(value)


def _coerce_hex_bytes(value, expected_length):
    if isinstance(value, str):
        value = bytes.fromhex(value)
    else:
        value = _coerce_bytes(value)

    if len(value) != expected_length:
        raise ValueError(f"Expected {expected_length} bytes, got {len(value)}.")
    return value


def chiffrement_des(texte_clair, cle_hex):
    key = _coerce_hex_bytes(cle_hex, 8)
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = _coerce_bytes(texte_clair)
    return cipher.encrypt(pad(plaintext, DES.block_size)).hex().upper()


def dechiffrement_des(texte_chiffre_hex, cle_hex):
    key = _coerce_hex_bytes(cle_hex, 8)
    ciphertext = bytes.fromhex(texte_chiffre_hex) if isinstance(texte_chiffre_hex, str) else _coerce_bytes(texte_chiffre_hex)
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return plaintext.decode()


def chiffrement_cbc(texte_clair, cle_hex, iv_hex):
    key = _coerce_hex_bytes(cle_hex, 8)
    iv = _coerce_hex_bytes(iv_hex, 8)
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    plaintext = _coerce_bytes(texte_clair)
    return cipher.encrypt(pad(plaintext, DES.block_size)).hex().upper()


def dechiffrement_cbc(texte_chiffre_hex, cle_hex, iv_hex):
    key = _coerce_hex_bytes(cle_hex, 8)
    iv = _coerce_hex_bytes(iv_hex, 8)
    ciphertext = bytes.fromhex(texte_chiffre_hex) if isinstance(texte_chiffre_hex, str) else _coerce_bytes(texte_chiffre_hex)
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return plaintext.decode()


def chiffrement_3des_cbc(texte_clair, cle_hex, iv_hex):
    key = _coerce_bytes(bytes.fromhex(cle_hex) if isinstance(cle_hex, str) else cle_hex)
    if len(key) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes.")

    iv = _coerce_hex_bytes(iv_hex, 8)
    cipher = DES3.new(DES3.adjust_key_parity(key), DES3.MODE_CBC, iv=iv)
    plaintext = _coerce_bytes(texte_clair)
    return cipher.encrypt(pad(plaintext, DES3.block_size)).hex().upper()


def dechiffrement_3des_cbc(texte_chiffre_hex, cle_hex, iv_hex):
    key = _coerce_bytes(bytes.fromhex(cle_hex) if isinstance(cle_hex, str) else cle_hex)
    if len(key) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes.")

    iv = _coerce_hex_bytes(iv_hex, 8)
    ciphertext = bytes.fromhex(texte_chiffre_hex) if isinstance(texte_chiffre_hex, str) else _coerce_bytes(texte_chiffre_hex)
    cipher = DES3.new(DES3.adjust_key_parity(key), DES3.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
    return plaintext.decode()


def __main__():
    print("=" * 50)
    print("   ALGORITHME DE CHIFFREMENT DES")
    print("=" * 50)

    cle = "133457799BBCDFF1"
    iv = "0000000000000000"
    message = "Bonjour!"

    print(f"\nMessage original  : {message}")
    print(f"Cle (hex)         : {cle}")

    print("\n--- Mode ECB ---")
    chiffre_ecb = chiffrement_des(message, cle)
    print(f"Texte chiffre     : {chiffre_ecb}")
    dechiffre_ecb = dechiffrement_des(chiffre_ecb, cle)
    print(f"Texte dechiffre   : {dechiffre_ecb}")

    print("\n--- Mode CBC ---")
    print(f"IV (hex)          : {iv}")
    chiffre_cbc = chiffrement_cbc(message, cle, iv)
    print(f"Texte chiffre     : {chiffre_cbc}")
    dechiffre_cbc = dechiffrement_cbc(chiffre_cbc, cle, iv)
    print(f"Texte dechiffre   : {dechiffre_cbc}")

    print("\n--- 3DES CBC ---")
    cle_3des = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF"
    chiffre_3des = chiffrement_3des_cbc(message, cle_3des, iv)
    print(f"Texte chiffre     : {chiffre_3des}")
    print(f"Texte dechiffre   : {dechiffrement_3des_cbc(chiffre_3des, cle_3des, iv)}")


if __name__ == "__main__":
    __main__()
