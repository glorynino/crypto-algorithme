"""
common/crypto_utils.py
Utilitaires cryptographiques partagés entre tous les exercices.
- Génération de clés RSA
- Chiffrement/Déchiffrement AES (CBC)
- Chiffrement/Déchiffrement RSA
- Signature / Vérification HMAC
- Hachage SHA-256
"""

import os
import hmac
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ─────────────────────────── RSA ───────────────────────────

def generate_rsa_keypair(key_size: int = 2048):
    """Génère une paire de clés RSA (privée, publique)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key) -> bytes:
    """Sérialise une clé publique RSA en PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(pem_data: bytes):
    """Désérialise une clé publique RSA depuis PEM."""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    """Chiffre des données avec la clé publique RSA (OAEP)."""
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Déchiffre des données avec la clé privée RSA (OAEP)."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_sign(private_key, data: bytes) -> bytes:
    """Signe des données avec la clé privée RSA (PSS)."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rsa_verify(public_key, signature: bytes, data: bytes) -> bool:
    """Vérifie une signature RSA. Retourne True si valide."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ─────────────────────────── AES ───────────────────────────

def generate_aes_key(key_size: int = 32) -> bytes:
    """Génère une clé AES aléatoire (32 bytes = AES-256)."""
    return os.urandom(key_size)


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Chiffre avec AES-256-CBC.
    Retourne : IV (16 bytes) + ciphertext
    """
    iv = os.urandom(16)
    # Padding PKCS7 manuel
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """
    Déchiffre avec AES-256-CBC.
    Attend : IV (16 bytes) + ciphertext
    """
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # Enlever padding PKCS7
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]


# ─────────────────────────── HMAC / Hash ───────────────────────────

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """Calcule un HMAC-SHA256 pour l'intégrité."""
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(key: bytes, data: bytes, mac: bytes) -> bool:
    """Vérifie un HMAC-SHA256. Retourne True si valide."""
    expected = compute_hmac(key, data)
    return hmac.compare_digest(expected, mac)


def sha256(data: bytes) -> bytes:
    """Retourne le hash SHA-256 des données."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Retourne le hash SHA-256 en hexadécimal."""
    return hashlib.sha256(data).hexdigest()
