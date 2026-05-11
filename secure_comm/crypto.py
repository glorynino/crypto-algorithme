"""Crypto helpers for the terminal secure chat demo."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_rsa_keypair(key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def save_private_key(private_key, path: str | Path, password: str | None = None):
    encryption_algorithm = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )
    Path(path).write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )
    )


def save_public_key(public_key, path: str | Path):
    Path(path).write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key(path: str | Path, password: str | None = None):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=password.encode() if password else None)


def load_public_key(path: str | Path):
    data = Path(path).read_bytes()
    return serialization.load_pem_public_key(data)


def rsa_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, data: bytes) -> bytes:
    return private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def pack_frame(key: bytes, plaintext: str) -> bytes:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return nonce + ciphertext


def unpack_frame(key: bytes, frame: bytes) -> str:
    if len(frame) < 13:
        raise ValueError("Invalid encrypted frame.")
    nonce, ciphertext = frame[:12], frame[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()


def sha256_fingerprint(public_key) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw)
    return digest.finalize().hex()
