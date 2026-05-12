"""
ECDSA (Elliptic Curve Digital Signature Algorithm)
Modern signature standard used in Bitcoin, TLS 1.3, etc.
Offers smaller keys than RSA/DSA for same security
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


class Point:
    """Elliptic curve point."""
    
    def __init__(self, x, y=None, curve=None):
        self.x = x
        self.y = y
        self.curve = curve
        self.is_infinity = (x is None and y is None)
    
    def __add__(self, other):
        """Point addition on elliptic curve."""
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        
        p = self.curve.p
        a = self.curve.a
        
        if self.x == other.x:
            if self.y == other.y:
                # Point doubling
                s = (3 * self.x * self.x + a) * mod_inverse(2 * self.y, p) % p
            else:
                # Result is point at infinity
                return Point(None, None, self.curve)
        else:
            # Regular addition
            s = (other.y - self.y) * mod_inverse(other.x - self.x, p) % p
        
        x3 = (s * s - self.x - other.x) % p
        y3 = (s * (self.x - x3) - self.y) % p
        
        return Point(x3, y3, self.curve)
    
    def __mul__(self, k):
        """Scalar multiplication."""
        if k == 0:
            return Point(None, None, self.curve)
        
        result = Point(None, None, self.curve)  # Point at infinity
        addend = self
        
        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        
        return result


class EllipticCurve:
    """y^2 = x^3 + ax + b (mod p)"""
    
    def __init__(self, a, b, p, n, g_x, g_y):
        """
        a, b: curve parameters
        p: prime modulus
        n: order of generator
        g_x, g_y: generator point
        """
        self.a = a
        self.b = b
        self.p = p
        self.n = n
        self.g = Point(g_x, g_y, self)
    
    def contains_point(self, x, y):
        """Check if point is on curve."""
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0


class ECDSA:
    """Elliptic Curve Digital Signature Algorithm."""
    
    def __init__(self, curve, d=None):
        """
        curve: EllipticCurve instance
        d: private key (optional)
        """
        self.curve = curve
        self.d = d
        self.Q = curve.g * d if d else None  # public key
    
    def sign(self, message):
        """Sign a message using ECDSA."""
        if self.d is None:
            raise ValueError("Private key not available")
        
        # Hash message
        h = hashlib.sha256(message).digest()
        z = int.from_bytes(h, 'big') % self.curve.n
        
        while True:
            # Generate random k
            k = random.randint(1, self.curve.n - 1)
            
            # Compute R = k*G
            R = self.curve.g * k
            
            if R.is_infinity:
                continue
            
            # r = R.x mod n
            r = R.x % self.curve.n
            
            if r == 0:
                continue
            
            # s = k^-1 * (z + r*d) mod n
            k_inv = mod_inverse(k, self.curve.n)
            s = (k_inv * (z + r * self.d)) % self.curve.n
            
            if s == 0:
                continue
            
            return (r, s)
    
    def verify(self, message, signature):
        """Verify an ECDSA signature."""
        if self.Q is None:
            raise ValueError("Public key not available")
        
        r, s = signature
        
        # Check validity
        if not (0 < r < self.curve.n and 0 < s < self.curve.n):
            return False
        
        # Hash message
        h = hashlib.sha256(message).digest()
        z = int.from_bytes(h, 'big') % self.curve.n
        
        # Compute w = s^-1 mod n
        try:
            w = mod_inverse(s, self.curve.n)
        except ValueError:
            return False
        
        # Compute u1 = z*w mod n, u2 = r*w mod n
        u1 = (z * w) % self.curve.n
        u2 = (r * w) % self.curve.n
        
        # Compute P = u1*G + u2*Q
        P = self.curve.g * u1 + self.Q * u2
        
        if P.is_infinity:
            return False
        
        # Verify r == P.x mod n
        return r == (P.x % self.curve.n)


if __name__ == "__main__":
    print("ECDSA (Elliptic Curve Digital Signature Algorithm)")
    print("=" * 60)
    
    # Simple curve for demo: y^2 = x^3 + 2x + 2 (mod 17)
    # This is too small for real crypto but good for testing
    p = 17
    a = 2
    b = 2
    n = 19  # Order of generator (simplified)
    gx, gy = 5, 1
    
    curve = EllipticCurve(a, b, p, n, gx, gy)
    
    print(f"\nElliptic Curve: y^2 = x^3 + {a}x + {b} (mod {p})")
    print(f"Generator: G = ({gx}, {gy})")
    print(f"Order: n = {n}")
    
    # Generate keypair
    d = random.randint(1, n - 1)
    print(f"Private key d = {d}")
    
    # Create signer
    signer = ECDSA(curve, d)
    Q = curve.g * d
    print(f"Public key Q = ({Q.x}, {Q.y})")
    
    # Test message
    message = b"Bitcoin signature"
    
    # Sign
    print("\n1. Signing message:")
    sig = signer.sign(message)
    print(f"Message: {message}")
    print(f"Signature: r={sig[0]}, s={sig[1]}")
    
    # Verify
    print("\n2. Verifying signature:")
    verifier = ECDSA(curve)
    verifier.Q = Q
    
    is_valid = verifier.verify(message, sig)
    print(f"Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    # Test tampering
    print("\n3. Testing tampering:")
    tampered = b"Bitcoin forged signature"
    is_valid = verifier.verify(tampered, sig)
    print(f"Tampered message: {'✓ VALID (FAIL!)' if is_valid else '✗ INVALID (expected)'}")
