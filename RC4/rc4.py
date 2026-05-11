"""RC4 implementation for educational use."""

from __future__ import annotations

from typing import Iterable


def _coerce_bytes(value: str | bytes | bytearray | Iterable[int]) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode()
    return bytes(value)


def _ksa(key_bytes: bytes) -> list[int]:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key_bytes[i % len(key_bytes)]) % 256
        state[i], state[j] = state[j], state[i]
    return state


def _prga(state: list[int], length: int) -> bytes:
    i = 0
    j = 0
    output = bytearray()
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
        keystream_byte = state[(state[i] + state[j]) % 256]
        output.append(keystream_byte)
    return bytes(output)


def encryption(key, message):
    key_bytes = _coerce_bytes(key)
    message_bytes = _coerce_bytes(message)

    if not key_bytes:
        raise ValueError("RC4 key cannot be empty.")

    state = _ksa(key_bytes)
    keystream = _prga(state, len(message_bytes))
    ciphertext = bytes(left ^ right for left, right in zip(message_bytes, keystream))
    return list(ciphertext)


def decryption(key, encrypted_message):
    key_bytes = _coerce_bytes(key)
    ciphertext = _coerce_bytes(encrypted_message)

    if not key_bytes:
        raise ValueError("RC4 key cannot be empty.")

    state = _ksa(key_bytes)
    keystream = _prga(state, len(ciphertext))
    plaintext = bytes(left ^ right for left, right in zip(ciphertext, keystream))
    result = plaintext.decode()
    print("Message dechiffre :", result)
    return result


if __name__ == "__main__":
    key = input("Veuillez entrer la cle de chiffrement : ")
    message = input("Veuillez entrer le message a chiffrer : ")

    encrypted_message = encryption(key, message)
    decryption(key, encrypted_message)