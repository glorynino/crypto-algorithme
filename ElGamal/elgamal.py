"""
ElGamal Cryptosystem - Educational Implementation
Based on Diffie-Hellman, prone to various attacks if not careful
"""

import random
from typing import Tuple


class ElGamalParams:
    """ElGamal system parameters (p, g)"""
    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g


class ElGamalKey:
    """ElGamal keypair"""
    
    def __init__(self, params: ElGamalParams, private_key=None):
        self.params = params
        # Private key: x in [2, p-2]
        self.private_key = private_key or random.randint(2, params.p - 2)
        # Public key: h = g^x mod p
        self.public_key = pow(params.g, self.private_key, params.p)
    
    def get_public_key(self):
        return self.public_key
    
    def get_private_key(self):
        return self.private_key


def elgamal_encrypt(params: ElGamalParams, public_key: int, plaintext: int) -> Tuple[int, int]:
    """
    ElGamal encryption
    
    Args:
        params: ElGamal parameters
        public_key: h = g^x mod p
        plaintext: message to encrypt
        
    Returns:
        (c1, c2) ciphertext tuple where:
        c1 = g^k mod p
        c2 = h^k * m mod p
    """
    if not (0 < plaintext < params.p):
        raise ValueError("Plaintext must be in [1, p-1]")
    
    # Generate random ephemeral key k
    k = random.randint(1, params.p - 2)
    
    # Compute c1 = g^k mod p
    c1 = pow(params.g, k, params.p)
    
    # Compute c2 = h^k * m mod p
    shared = pow(public_key, k, params.p)
    c2 = (shared * plaintext) % params.p
    
    return (c1, c2)


def elgamal_decrypt(params: ElGamalParams, private_key: int, ciphertext: Tuple[int, int]) -> int:
    """
    ElGamal decryption
    
    Args:
        params: ElGamal parameters
        private_key: x
        ciphertext: (c1, c2)
        
    Returns:
        Decrypted plaintext
    """
    c1, c2 = ciphertext
    
    # Compute shared secret: (c1^x) mod p = (g^(kx)) mod p
    shared = pow(c1, private_key, params.p)
    
    # Recover plaintext: m = c2 / shared mod p = c2 * shared^(-1) mod p
    shared_inv = pow(shared, params.p - 2, params.p)  # FLT: a^(-1) = a^(p-2) mod p
    plaintext = (c2 * shared_inv) % params.p
    
    return plaintext


def test_elgamal():
    """Test basic ElGamal encryption"""
    print("\n" + "=" * 70)
    print("BASIC ELGAMAL TEST")
    print("=" * 70 + "\n")
    
    p = 1000000007
    g = 2
    params = ElGamalParams(p, g)
    
    print(f"Parameters:")
    print(f"  p = {p}")
    print(f"  g = {g}\n")
    
    # Generate keypair
    alice = ElGamalKey(params)
    print(f"Alice's private key: x = {alice.private_key}")
    print(f"Alice's public key:  h = {alice.public_key}\n")
    
    # Encrypt
    plaintext = 123456
    print(f"Plaintext: {plaintext}")
    
    c1, c2 = elgamal_encrypt(params, alice.public_key, plaintext)
    print(f"Ciphertext: ({c1}, {c2})\n")
    
    # Decrypt
    recovered = elgamal_decrypt(params, alice.private_key, (c1, c2))
    print(f"Decrypted: {recovered}")
    print(f"Match: {recovered == plaintext} ✓\n")


if __name__ == "__main__":
    test_elgamal()
    print("=" * 70)
