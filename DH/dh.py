"""
Diffie-Hellman Key Exchange - Educational Implementation
Basic FFDH (Finite Field Diffie-Hellman)
"""

import random
from typing import Tuple


class DH_Parameters:
    """Diffie-Hellman parameters (p, g)"""
    
    def __init__(self, p: int, g: int):
        """
        Args:
            p: Large prime modulus
            g: Generator (non-identity element of multiplicative group mod p)
        """
        self.p = p  # Prime modulus
        self.g = g  # Generator


class DH:
    """Diffie-Hellman key exchange party"""
    
    def __init__(self, params: DH_Parameters):
        """
        Initialize DH participant with shared parameters
        
        Args:
            params: DH_Parameters with p and g
        """
        self.params = params
        
        # Generate random private key: 2 ≤ x ≤ p-2
        self.private_key = random.randint(2, params.p - 2)
        
        # Compute public key: y ≡ g^x mod p
        self.public_key = pow(params.g, self.private_key, params.p)
    
    def get_public_key(self) -> int:
        """Get this party's public key"""
        return self.public_key
    
    def get_private_key(self) -> int:
        """Get this party's private key (for demo only)"""
        return self.private_key
    
    def set_private_key(self, private_key: int):
        """Set private key manually (for attacks/demos)"""
        self.private_key = private_key
        self.public_key = pow(self.params.g, private_key, self.params.p)
    
    def compute_shared_secret(self, other_public_key: int) -> int:
        """
        Compute shared secret from other party's public key
        
        Args:
            other_public_key: The other party's public key
            
        Returns:
            Shared secret: K ≡ (other_public_key)^(private_key) mod p
        """
        shared_secret = pow(other_public_key, self.private_key, self.params.p)
        return shared_secret
    
    def __repr__(self):
        return f"DH(priv={self.private_key}, pub={self.public_key})"


def test_basic_dh():
    """Test basic DH key exchange"""
    print("\n" + "=" * 70)
    print("BASIC DIFFIE-HELLMAN KEY EXCHANGE TEST")
    print("=" * 70 + "\n")
    
    # Use RFC 3526 2048-bit group (simplified for demo)
    p = 1000000007  # Large prime
    g = 2
    
    print(f"Public parameters:")
    print(f"  p = {p}")
    print(f"  g = {g}\n")
    
    # Create Alice and Bob
    params = DH_Parameters(p=p, g=g)
    alice = DH(params)
    bob = DH(params)
    
    print(f"Alice's keypair:")
    print(f"  Private: a = {alice.get_private_key()}")
    print(f"  Public:  A = g^a mod p = {alice.get_public_key()}\n")
    
    print(f"Bob's keypair:")
    print(f"  Private: b = {bob.get_private_key()}")
    print(f"  Public:  B = g^b mod p = {bob.get_public_key()}\n")
    
    # Exchange public keys and compute shared secret
    shared_alice = alice.compute_shared_secret(bob.get_public_key())
    shared_bob = bob.compute_shared_secret(alice.get_public_key())
    
    print(f"Alice computes:")
    print(f"  K = B^a mod p = {shared_alice}\n")
    
    print(f"Bob computes:")
    print(f"  K = A^b mod p = {shared_bob}\n")
    
    print(f"Shared secret match: {shared_alice == shared_bob} ✓\n")
    
    print(f"Security analysis:")
    print(f"  Eavesdropper knows: p, g, A={alice.get_public_key()}, B={bob.get_public_key()}")
    print(f"  Eavesdropper needs: discrete log to recover a or b")
    print(f"  With p={p} bits, log_2(p) = {p.bit_length()} bits")
    print(f"  Discrete log is hard for large p")


if __name__ == "__main__":
    test_basic_dh()
    print("=" * 70)
