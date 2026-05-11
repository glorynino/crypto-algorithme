"""Hill cipher implementation for 2x2 and 3x3 matrices."""

from __future__ import annotations

import math
from collections.abc import Sequence

from sympy import Matrix

ALPHABET_SIZE = 26
ALPHABET_START = ord("A")


def _normalize_text(text: str) -> str:
    return "".join(char.upper() for char in text if char.isalpha())


def _normalize_pad(pad_char: str) -> str:
    if len(pad_char) != 1 or not pad_char.isalpha():
        raise ValueError("pad_char must be a single alphabetic character.")
    return pad_char.upper()


def _flatten_key(key: Sequence[Sequence[int]] | Sequence[int]) -> list[int]:
    if not key:
        raise ValueError("Hill key cannot be empty.")

    first_item = key[0]
    if isinstance(first_item, Sequence) and not isinstance(first_item, (bytes, bytearray, str)):
        rows = [list(row) for row in key]  # type: ignore[arg-type]
        size = len(rows)
        if any(len(row) != size for row in rows):
            raise ValueError("Hill key matrix must be square.")
        return [int(value) for row in rows for value in row]

    flat = [int(value) for value in key]  # type: ignore[arg-type]
    size = int(len(flat) ** 0.5)
    if size * size != len(flat):
        raise ValueError("Flat Hill key must describe a square matrix.")
    return flat


def _to_matrix(key: Sequence[Sequence[int]] | Sequence[int]) -> Matrix:
    flat = _flatten_key(key)
    size = int(len(flat) ** 0.5)
    matrix = Matrix(size, size, flat).applyfunc(lambda value: int(value) % ALPHABET_SIZE)

    determinant = int(matrix.det()) % ALPHABET_SIZE
    if math.gcd(determinant, ALPHABET_SIZE) != 1:
        raise ValueError("Hill key matrix is not invertible modulo 26.")

    return matrix


def _numbers_to_text(values) -> str:
    return "".join(chr((int(value) % ALPHABET_SIZE) + ALPHABET_START) for value in values)


def _chunk_text(text: str, size: int, pad_char: str) -> str:
    normalized = _normalize_text(text)
    remainder = len(normalized) % size
    if remainder:
        normalized += pad_char * (size - remainder)
    return normalized


def _transform_blocks(text: str, matrix: Matrix) -> str:
    size = matrix.rows
    normalized = _chunk_text(text, size, "X")
    output = []

    for index in range(0, len(normalized), size):
        block = normalized[index:index + size]
        vector = Matrix([ord(char) - ALPHABET_START for char in block])
        transformed = matrix * vector
        output.append(_numbers_to_text(transformed))

    return "".join(output)


def encrypt_hill(text: str, key: Sequence[Sequence[int]] | Sequence[int], pad_char: str = "X") -> str:
    """Encrypt text with a Hill cipher key matrix."""
    matrix = _to_matrix(key)
    pad_char = _normalize_pad(pad_char)

    normalized = _chunk_text(text, matrix.rows, pad_char)
    output = []
    for index in range(0, len(normalized), matrix.rows):
        block = normalized[index:index + matrix.rows]
        vector = Matrix([ord(char) - ALPHABET_START for char in block])
        transformed = matrix * vector
        output.append(_numbers_to_text(transformed))
    return "".join(output)


def decrypt_hill(text: str, key: Sequence[Sequence[int]] | Sequence[int], pad_char: str = "X") -> str:
    """Decrypt text with a Hill cipher key matrix."""
    matrix = _to_matrix(key)
    inverse = matrix.inv_mod(ALPHABET_SIZE)
    pad_char = _normalize_pad(pad_char)

    normalized = _normalize_text(text)
    if len(normalized) % inverse.rows != 0:
        raise ValueError("Ciphertext length must be a multiple of the Hill block size.")

    output = []
    for index in range(0, len(normalized), inverse.rows):
        block = normalized[index:index + inverse.rows]
        vector = Matrix([ord(char) - ALPHABET_START for char in block])
        transformed = inverse * vector
        output.append(_numbers_to_text(transformed))

    return "".join(output).rstrip(pad_char)


def recover_key_from_known_plaintext(plaintext: str, ciphertext: str, size: int) -> Matrix:
    """Recover a Hill key from a known plaintext/ciphertext pair."""
    plain = _normalize_text(plaintext)
    cipher = _normalize_text(ciphertext)

    if len(plain) < size * size or len(cipher) < size * size:
        raise ValueError("Need at least size^2 letters of plaintext and ciphertext.")

    plain_blocks = [plain[index:index + size] for index in range(0, size * size, size)]
    cipher_blocks = [cipher[index:index + size] for index in range(0, size * size, size)]

    plain_matrix = Matrix(
        [[ord(block[row]) - ALPHABET_START for block in plain_blocks] for row in range(size)]
    )
    cipher_matrix = Matrix(
        [[ord(block[row]) - ALPHABET_START for block in cipher_blocks] for row in range(size)]
    )

    determinant = int(plain_matrix.det()) % ALPHABET_SIZE
    if math.gcd(determinant, ALPHABET_SIZE) != 1:
        raise ValueError("Selected plaintext blocks are not invertible modulo 26.")

    return (cipher_matrix * plain_matrix.inv_mod(ALPHABET_SIZE)).applyfunc(
        lambda value: int(value) % ALPHABET_SIZE
    )


def hill_cipher():
    key_2x2 = [[3, 3], [2, 5]]
    message = "HELLO WORLD"
    print(encrypt_hill(message, key_2x2))


def hill_decipher():
    key_2x2 = [[3, 3], [2, 5]]
    message = encrypt_hill("HELLO WORLD", key_2x2)
    print(decrypt_hill(message, key_2x2))


def __main__():
    hill_cipher()
    hill_decipher()


if __name__ == "__main__":
    __main__()
