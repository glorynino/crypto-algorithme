"""
DSA (Digital Signature Algorithm)
Standard signature algorithm used by US government
Fixes ElGamal to be shorter and more practical
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


class DSA:
    """Digital Signature Algorithm."""
    
    def __init__(self, p, q, g, x=None):
        """
        Initialize DSA.
        p: large prime (modulus)
        q: prime divisor of p-1
        g: generator of order q
        x: private key (0 < x < q)
        """
        self.p = p
        self.q = q
        self.g = g
        self.x = x
        self.y = pow(g, x, p) if x else None  # public key: y = g^x mod p
    
    def sign(self, message):
        """Sign a message using DSA."""
        if self.x is None:
            raise ValueError("Private key not available")
        
        # Hash message (use SHA-1 as per original DSA spec, or SHA-256 for modern)
        h = hashlib.sha256(message).digest()
        z = int.from_bytes(h[:self.q.bit_length() // 8], 'big') % self.q
        
        while True:
            # Generate random k
            k = random.randint(1, self.q - 1)
            
            # Compute r = (g^k mod p) mod q
            r = pow(self.g, k, self.p) % self.q
            
            if r == 0:
                continue
            
            # Compute s = k^-1 * (z + x*r) mod q
            k_inv = mod_inverse(k, self.q)
            s = (k_inv * (z + self.x * r)) % self.q
            
            if s == 0:
                continue
            
            return (r, s)
    
    def verify(self, message, signature):
        """Verify a DSA signature."""
        if self.y is None:
            raise ValueError("Public key not available")
        
        r, s = signature
        
        # Check validity
        if not (0 < r < self.q and 0 < s < self.q):
            return False
        
        # Hash message
        h = hashlib.sha256(message).digest()
        z = int.from_bytes(h[:self.q.bit_length() // 8], 'big') % self.q
        
        # Compute w = s^-1 mod q
        try:
            w = mod_inverse(s, self.q)
        except ValueError:
            return False
        
        # Compute u1 = z*w mod q, u2 = r*w mod q
        u1 = (z * w) % self.q
        u2 = (r * w) % self.q
        
        # Compute v = (g^u1 * y^u2 mod p) mod q
        v = (pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p % self.q
        
        # Verify v == r
        return v == r


if __name__ == "__main__":
    print("DSA (Digital Signature Algorithm)")
    print("=" * 60)
    
    # DSA parameters (example, normally these are pre-agreed)
    # For demo: small values
    p = 1000000007
    q = 500000003
    g = 2
    x = random.randint(1, q - 1)
    
    print(f"\nDSA Parameters:")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  g = {g}")
    print(f"  Private key x = {x}")
    
    # Create signer
    signer = DSA(p, q, g, x)
    print(f"  Public key y = {signer.y}")
    
    # Test message
    message = b"I agree to sign this contract"
    
    # Sign message
    print("\n1. Signing message:")
    sig = signer.sign(message)
    print(f"Message: {message}")
    print(f"Signature: r={sig[0]}, s={sig[1]}")
    
    # Verify signature
    print("\n2. Verifying signature:")
    verifier = DSA(p, q, g)
    verifier.y = signer.y
    
    is_valid = verifier.verify(message, sig)
    print(f"Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    # Test tampering
    print("\n3. Testing tampering detection:")
    tampered = b"I agree to sign this CONTRACT"
    is_valid = verifier.verify(tampered, sig)
    print(f"Tampered message: {'✓ VALID (FAIL!)' if is_valid else '✗ INVALID (expected)'}")
    
    # Test bad signature
    bad_sig = (sig[0], (sig[1] + 1) % signer.q)
    is_valid = verifier.verify(message, bad_sig)
    print(f"Modified signature: {'✓ VALID (FAIL!)' if is_valid else '✗ INVALID (expected)'}")
