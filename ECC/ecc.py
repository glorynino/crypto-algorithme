"""
Elliptic Curve Cryptography - Educational Implementation
ECDH (Elliptic Curve Diffie-Hellman) and ECDSA (Elliptic Curve DSA)
"""

import random
from typing import Tuple


class ECC_Point:
    """Point on elliptic curve y^2 ≡ x^3 + ax + b (mod p)"""
    
    def __init__(self, x=None, y=None, curve=None):
        self.x = x
        self.y = y
        self.curve = curve
        self.is_infinity = (x is None and y is None)
    
    def __add__(self, other):
        """Point addition on elliptic curve"""
        if other.is_infinity:
            return self
        if self.is_infinity:
            return other
        
        p = self.curve.p
        
        # Point doubling
        if self.x == other.x:
            if self.y == other.y:
                # 2P: slope = (3x^2 + a) / 2y
                s = (3 * self.x ** 2 + self.curve.a) * pow(2 * self.y, p - 2, p) % p
            else:
                # P + (-P) = O
                return ECC_Point(curve=self.curve)
        else:
            # P + Q: slope = (y2 - y1) / (x2 - x1)
            s = (other.y - self.y) * pow(other.x - self.x, p - 2, p) % p
        
        # x3 = s^2 - x1 - x2
        x3 = (s ** 2 - self.x - other.x) % p
        # y3 = s(x1 - x3) - y1
        y3 = (s * (self.x - x3) - self.y) % p
        
        return ECC_Point(x3, y3, self.curve)
    
    def __mul__(self, scalar):
        """Scalar multiplication using double-and-add"""
        if scalar == 0:
            return ECC_Point(curve=self.curve)  # Infinity
        if scalar < 0:
            # Negate point
            neg_point = ECC_Point(self.x, (-self.y) % self.curve.p, self.curve)
            return neg_point * (-scalar)
        
        result = ECC_Point(curve=self.curve)  # Infinity
        addend = self
        
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1
        
        return result
    
    def __rmul__(self, scalar):
        return self * scalar
    
    def __repr__(self):
        if self.is_infinity:
            return "O (point at infinity)"
        return f"({self.x}, {self.y})"


class EllipticCurve:
    """Elliptic Curve: y^2 ≡ x^3 + ax + b (mod p)"""
    
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p
    
    def point(self, x, y):
        """Create point on this curve"""
        return ECC_Point(x, y, self)
    
    def has_point(self, x, y):
        """Check if (x, y) is on curve"""
        return (y ** 2) % self.p == (x ** 3 + self.a * x + self.b) % self.p


def ecdh_example():
    """ECDH Key Exchange using small curve for demo"""
    print("\n" + "=" * 70)
    print("ECDH BASIC EXAMPLE (Small Curve for Demo)")
    print("=" * 70 + "\n")
    
    # secp192r1 reduced (demo size)
    p = 6277101735386680763835789423207666416083908700390324961279
    a = -3
    b = 2455155546008943817740293915197451784769108058161191238065
    
    # Base point
    Gx = 602046282375688656601964616666194642317432387279335085969643
    Gy = 174050332293622031404857552280219410364023553197256146129584
    G_order = 6277101735386680763835789423176059013767194773182842284081
    
    curve = EllipticCurve(a, b, p)
    G = curve.point(Gx, Gy)
    
    print(f"Elliptic Curve: y^2 = x^3 + {a}x + {b} (mod {p})")
    print(f"Base point G = ({Gx}, {Gy})")
    print(f"Order of G: {G_order}\n")
    
    # Alice
    a_priv = random.randint(1, G_order - 1)
    A = a_priv * G
    print(f"Alice's private key: a = {a_priv}")
    print(f"Alice's public key:  A = a·G = ({A.x}, {A.y})\n")
    
    # Bob
    b_priv = random.randint(1, G_order - 1)
    B = b_priv * G
    print(f"Bob's private key: b = {b_priv}")
    print(f"Bob's public key:  B = b·G = ({B.x}, {B.y})\n")
    
    # Shared secret
    K_alice = a_priv * B
    K_bob = b_priv * A
    
    print(f"Shared secret (Alice): K = a·B = ({K_alice.x}, {K_alice.y})")
    print(f"Shared secret (Bob):   K = b·A = ({K_bob.x}, {K_bob.y})")
    print(f"Match: {K_alice.x == K_bob.x and K_alice.y == K_bob.y} ✓\n")


def ecdsa_signature_example():
    """ECDSA Digital Signature"""
    print("\n" + "=" * 70)
    print("ECDSA DIGITAL SIGNATURE EXAMPLE")
    print("=" * 70 + "\n")
    
    print("ECDSA Components:")
    print("  Private key: d (random integer 1 < d < n)")
    print("  Public key:  Q = d·G (point on curve)")
    print("  Message hash: h (output of SHA-2 or similar)\n")
    
    print("Signing:")
    print("  1. Generate random k, compute R = k·G = (r, y)")
    print("  2. Compute r = R.x mod n")
    print("  3. Compute s = k^(-1)(h + r·d) mod n")
    print("  4. Signature: (r, s)\n")
    
    print("Verification:")
    print("  1. Receive (r, s) and message hash h")  
    print("  2. Compute w = s^(-1) mod n")
    print("  3. Compute u1 = h·w mod n")
    print("  4. Compute u2 = r·w mod n")
    print("  5. Compute (x, y) = u1·G + u2·Q")
    print("  6. Valid if x mod n = r\n")
    
    print("Security:")
    print("  • Requires k to be random (NOT predictable)")
    print("  • Leak of k completely breaks signature")
    print("  • k must never repeat (or same message/different message)")
    print("  • Sony PS3 jailbreak exploited k reuse")


def main():
    """Demonstrate ECC basics"""
    
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + " " * 12 + "ELLIPTIC CURVE CRYPTOGRAPHY BASICS" + " " * 20 + "║")
    print("╚" + "═" * 68 + "╝")
    
    ecdh_example()
    ecdsa_signature_example()
    
    print("\n" + "═" * 70)
    print("ECC ADVANTAGES OVER RSA/DH:")
    print("═" * 70)
    print("""
Security Level Comparison:
  ECC-256  ≈  RSA-3072  (256-bit security)
  ECC-384  ≈  RSA-7680  (384-bit security)
  
Advantages:
  ✓ Smaller keys for same security
  ✓ Faster operations
  ✓ Lower power consumption (mobile/IoT)
  ✓ Smaller signatures
  ✓ No known subexponential attacks (unlike RSA/DH)
  
Disadvantages:
  ✗ More complex math (finite field algebra)
  ✗ Requires carefully chosen curves
  ✗ Patent landscape (some curves/techniques)
  ✗ Implementation side-channels possible
  
Standard Curves (TLS):
  • secp256r1 (NIST P-256) - widely used
  • Curve25519 - high-speed, modern
  • secp384r1, secp521r1 - larger security
  
Modern Usage (2026):
  • TLS 1.3: Preferred handshake key exchange
  • Signal/WhatsApp: X25519 + Double Ratchet
  • Bitcoin/Ethereum: secp256k1
  • Post-Quantum: Hybrid with lattice-based (Kyber, Dilithium)
""")
    print("═" * 70 + "\n")


if __name__ == "__main__":
    main()
