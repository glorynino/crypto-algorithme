"""One-time pad helpers."""

from __future__ import annotations

import os
from typing import Iterable


def _coerce_bytes(value: str | bytes | bytearray | Iterable[int]) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode()
    return bytes(value)


def encryption(message):
    message_bytes = _coerce_bytes(message)
    key = os.urandom(len(message_bytes))
    ciphertext = bytes(left ^ right for left, right in zip(message_bytes, key))
    return ciphertext, key


def decryption(resultat, key):
    ciphertext = _coerce_bytes(resultat)
    key_bytes = _coerce_bytes(key)
    if len(ciphertext) != len(key_bytes):
        raise ValueError("Ciphertext and key must have the same length.")

    message = bytes(left ^ right for left, right in zip(ciphertext, key_bytes))
    return message.decode()


if __name__ == "__main__":
    message = "Hello World"
    print("Message:", message)
    resultat, key = encryption(message)
    print("Encrypted:", resultat)
    decrypted_message = decryption(resultat, key)
    print("Decrypted:", decrypted_message)