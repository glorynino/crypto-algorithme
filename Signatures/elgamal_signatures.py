"""
ElGamal Digital Signatures
Based on discrete logarithm problem
Similar structure to encryption but for signatures
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


def find_primitive_root(p):
    """Find generator of group Z_p*."""
    phi = p - 1
    factors = []
    temp = phi
    d = 2
    while d * d <= temp:
        while temp % d == 0:
            if d not in factors:
                factors.append(d)
            temp //= d
        d += 1
    if temp > 1:
        factors.append(temp)
    
    for g in range(2, p):
        is_primitive = True
        for factor in factors:
            if pow(g, phi // factor, p) == 1:
                is_primitive = False
                break
        if is_primitive:
            return g
    return None


class ElGamalSignature:
    """ElGamal Digital Signature Scheme."""
    
    def __init__(self, p, g, x=None):
        """
        Initialize with parameters.
        p: large prime
        g: generator
        x: private key (optional)
        """
        self.p = p
        self.g = g
        self.x = x
        self.y = pow(g, x, p) if x else None  # public key
    
    def sign(self, message):
        """Sign a message."""
        if self.x is None:
            raise ValueError("Private key not available")
        
        # Hash message
        h = hashlib.sha256(message).digest()
        m = int.from_bytes(h, 'big') % (self.p - 1)
        
        # Generate random k (must be coprime with p-1)
        while True:
            k = random.randint(1, self.p - 2)
            if gcd(k, self.p - 1) == 1:
                break
        
        # Compute signature components
        r = pow(self.g, k, self.p)
        k_inv = mod_inverse(k, self.p - 1)
        s = (k_inv * (m - self.x * r)) % (self.p - 1)
        
        # Ensure s is positive
        s = (s + self.p - 1) % (self.p - 1)
        
        return (r, s)
    
    def verify(self, message, signature):
        """Verify a signature."""
        if self.y is None:
            raise ValueError("Public key not available")
        
        r, s = signature
        
        # Check validity of signature components
        if not (0 < r < self.p and 0 < s < self.p - 1):
            return False
        
        # Hash message
        h = hashlib.sha256(message).digest()
        m = int.from_bytes(h, 'big') % (self.p - 1)
        
        # Verify: g^m ≡ y^r * r^s (mod p)
        left = pow(self.g, m, self.p)
        right = (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p
        
        return left == right


if __name__ == "__main__":
    print("ElGamal Digital Signatures")
    print("=" * 60)
    
    # Parameters
    p = 1000000007
    g = 2
    x = random.randint(1, p - 2)
    
    print(f"\nParameters:")
    print(f"  p = {p}")
    print(f"  g = {g}")
    print(f"  Private key x = {x}")
    
    # Create signer
    signer = ElGamalSignature(p, g, x)
    print(f"  Public key y = {signer.y}")
    
    # Test message
    message1 = b"First document to sign"
    message2 = b"Second document to sign"
    
    # Sign messages
    print("\n1. Signing messages:")
    sig1 = signer.sign(message1)
    sig2 = signer.sign(message2)
    print(f"Message 1: {message1}")
    print(f"Signature 1: r={sig1[0]}, s={sig1[1]}")
    print(f"\nMessage 2: {message2}")
    print(f"Signature 2: r={sig2[0]}, s={sig2[1]}")
    
    # Verify signatures
    print("\n2. Verification:")
    verifier = ElGamalSignature(p, g)
    verifier.y = signer.y
    
    is_valid1 = verifier.verify(message1, sig1)
    is_valid2 = verifier.verify(message2, sig2)
    
    print(f"Signature 1: {'✓ VALID' if is_valid1 else '✗ INVALID'}")
    print(f"Signature 2: {'✓ VALID' if is_valid2 else '✗ INVALID'}")
    
    # Test forgery attempt
    print("\n3. Forgery attempt:")
    forged_sig = (sig1[0], sig1[1])  # Try to use signature from message1 on message2
    is_valid = verifier.verify(message2, forged_sig)
    print(f"Forged signature: {'✓ VALID (FAIL!)' if is_valid else '✗ INVALID (expected)'}")
