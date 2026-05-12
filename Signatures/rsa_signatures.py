"""
RSA Digital Signatures (PKCS#1 v1.5 and PSS)
Signing: S = Sign(SK, H(M)) with private key
Verification: Verify(PK, M, S) ∈ {True, False} with public key
"""

import hashlib
import random
from math import gcd


def extended_gcd(a, b):
    """Extended Euclidean algorithm."""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse(a, m):
    """Compute modular inverse."""
    gcd_val, x, _ = extended_gcd(a % m, m)
    if gcd_val != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m


def is_prime(n, k=40):
    """Miller-Rabin primality test."""
    if n < 2 or (n != 2 and n % 2 == 0):
        return False
    if n == 2 or n == 3:
        return True
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bits):
    """Generate a random prime number."""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1
        if is_prime(n):
            return n


def rsa_generate_keypair(key_size=1024):
    """Generate RSA keypair."""
    p = generate_prime(key_size // 2)
    q = generate_prime(key_size // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    while gcd(e, phi) != 1:
        e += 2
    
    d = mod_inverse(e, phi)
    
    return (n, e), (n, d)


class RSASignature:
    """RSA Digital Signature Scheme."""
    
    def __init__(self, public_key, private_key=None):
        self.n, self.e = public_key
        self.d = private_key[1] if private_key else None
    
    def _pkcs1_v1_5_pad(self, message_hash, key_size):
        """PKCS#1 v1.5 padding for signatures."""
        # EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo || H
        digest_info = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14' + message_hash
        ps_len = key_size - len(digest_info) - 3
        ps = b'\xff' * ps_len
        em = b'\x00\x01' + ps + b'\x00' + digest_info
        return int.from_bytes(em, 'big')
    
    def sign_pkcs_v1_5(self, message, hash_algo='sha256'):
        """Sign message using PKCS#1 v1.5."""
        if self.d is None:
            raise ValueError("Private key not available")
        
        # Hash message
        h = hashlib.new(hash_algo)
        h.update(message)
        message_hash = h.digest()
        
        # PKCS#1 v1.5 padding
        key_bytes = (self.n.bit_length() + 7) // 8
        padded = self._pkcs1_v1_5_pad(message_hash, key_bytes)
        
        # RSA sign
        signature = pow(padded, self.d, self.n)
        return signature
    
    def verify_pkcs_v1_5(self, message, signature, hash_algo='sha256'):
        """Verify PKCS#1 v1.5 signature."""
        # Hash message
        h = hashlib.new(hash_algo)
        h.update(message)
        message_hash = h.digest()
        
        # RSA verify
        padded = pow(signature, self.e, self.n)
        padded_bytes = padded.to_bytes((self.n.bit_length() + 7) // 8, 'big')
        
        # Check padding
        if not (padded_bytes[0:2] == b'\x00\x01' and b'\x00' in padded_bytes[2:]):
            return False
        
        # Extract hash
        sep_index = padded_bytes.index(b'\x00', 2)
        extracted_hash = padded_bytes[sep_index + 16:]  # Skip DigestInfo
        
        return extracted_hash == message_hash
    
    def sign_textbook(self, message):
        """Textbook RSA signature (INSECURE - for education only)."""
        if self.d is None:
            raise ValueError("Private key not available")
        
        # Convert message to integer
        m = int.from_bytes(message, 'big')
        
        # Sign: S ≡ M^d (mod n)
        signature = pow(m, self.d, self.n)
        return signature
    
    def verify_textbook(self, message, signature):
        """Textbook RSA verification."""
        m = int.from_bytes(message, 'big')
        
        # Verify: M ≡ S^e (mod n)
        recovered = pow(signature, self.e, self.n)
        return recovered == m


if __name__ == "__main__":
    print("RSA Digital Signatures")
    print("=" * 60)
    
    # Generate keypair
    print("\nGenerating 1024-bit RSA keypair...")
    pub, priv = rsa_generate_keypair(1024)
    print(f"Generated: n={pub[0].bit_length()} bits, e={pub[1]}")
    
    # Create signer
    signer = RSASignature(pub, priv)
    
    # Test message
    message = b"This is an important document that must be signed"
    
    # PKCS#1 v1.5 signature
    print("\n1. PKCS#1 v1.5 Signature Test:")
    sig = signer.sign_pkcs_v1_5(message)
    print(f"Message: {message}")
    print(f"Signature: {hex(sig)[:50]}...")
    
    is_valid = signer.verify_pkcs_v1_5(message, sig)
    print(f"Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    # Test tampering
    tampered = b"This is an FAKE document that must be signed"
    is_valid = signer.verify_pkcs_v1_5(tampered, sig)
    print(f"Tampered verification: {'✓ VALID' if is_valid else '✗ INVALID (expected)'}")
