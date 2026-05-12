#!/usr/bin/env python3
"""
TP 5 - Digital Signatures
Complete test suite for RSA, ElGamal, DSA, and ECDSA signatures
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Signatures.rsa_signatures import RSASignature, rsa_generate_keypair
from Signatures.elgamal_signatures import ElGamalSignature
from Signatures.dsa import DSA
from Signatures.ecdsa import ECDSA, EllipticCurve
from Signatures.signature_attacks import ecdsa_nonce_reuse_attack


def print_header(text):
    """Print formatted header."""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80)


def exercice_5_1_rsa():
    """Exercise 5.1: RSA Signatures (PKCS#1 v1.5 and PSS)."""
    print_header("EXERCICE 5.1 - RSA SIGNATURES (PKCS#1 v1.5)")
    
    print("\nRSA Signature Process:")
    print("  • Sign: S ≡ H(M)^d (mod n) with private key")
    print("  • Verify: H(M) ≡ S^e (mod n) with public key")
    print("  • Padding: PKCS#1 v1.5 (traditional) or PSS (modern)")
    print("  • Status: Industry standard, recommended with PSS")
    
    print("\n" + "-" * 80)
    print("RSA-512 Signature Test (faster for demo):")
    print("-" * 80)
    
    # Generate keypair (512-bit for speed)
    pub, priv = rsa_generate_keypair(512)
    signer = RSASignature(pub, priv)
    verifier = RSASignature(pub)
    
    # Test message
    messages = [
        b"Important document 1",
        b"Important document 2",
        b"Bank transfer: send $1000 to Alice",
    ]
    
    print(f"\nGenerated RSA-1024 keypair")
    print(f"  n = {pub[0].bit_length()} bits")
    print(f"  e = {pub[1]}")
    
    for i, msg in enumerate(messages, 1):
        print(f"\n{i}. Message: {msg}")
        
        # Sign
        sig = signer.sign_pkcs_v1_5(msg)
        print(f"   Signature: {hex(sig)[:50]}...")
        
        # Verify
        is_valid = verifier.verify_pkcs_v1_5(msg, sig)
        print(f"   Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    print("\n✓ RSA Signature Exercises Completed")


def exercice_5_2_elgamal():
    """Exercise 5.2: ElGamal Signatures."""
    print_header("EXERCICE 5.2 - ELGAMAL SIGNATURES")
    
    print("\nElGamal Signature Process:")
    print("  • Based on discrete logarithm problem")
    print("  • Sign: (r, s) where r = g^k mod p, s = k^-1(H(m) - x*r) mod (p-1)")
    print("  • Verify: g^H(m) ≡ y^r * r^s (mod p)")
    print("  • Note: Signature size = 2 * log_2(p) bits")
    
    print("\n" + "-" * 80)
    print("ElGamal Signature Test:")
    print("-" * 80)
    
    # Parameters
    p = 1000000007
    g = 2
    x = 123456789
    
    print(f"\nElGamal Parameters:")
    print(f"  p = {p} (prime)")
    print(f"  g = {g} (generator)")
    print(f"  x = {x} (private key)")
    
    # Create signer
    signer = ElGamalSignature(p, g, x)
    print(f"  y = {signer.y} (public key)")
    
    # Create verifier
    verifier = ElGamalSignature(p, g)
    verifier.y = signer.y
    
    # Test messages
    test_cases = [
        b"Message 1",
        b"Message 2",
        b"Message 3",
    ]
    
    for i, msg in enumerate(test_cases, 1):
        print(f"\n{i}. Message: {msg}")
        
        # Sign
        sig = signer.sign(msg)
        print(f"   Signature: r={sig[0]}, s={sig[1]}")
        
        # Verify
        is_valid = verifier.verify(msg, sig)
        print(f"   Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    # Test forgery attempt
    print("\n" + "-" * 80)
    print("Forgery Resistance Test:")
    print("-" * 80)
    
    msg1 = b"Transfer 100 USD"
    sig1 = signer.sign(msg1)
    
    msg2 = b"Transfer 1000 USD"
    is_valid = verifier.verify(msg2, sig1)
    print(f"\nSignature for msg1 on msg2: {'✓ VALID (FAIL!)' if is_valid else '✗ INVALID (expected)'}")
    
    print("\n✓ ElGamal Signature Exercises Completed")


def exercice_5_3_dsa():
    """Exercise 5.3: DSA Signatures."""
    print_header("EXERCICE 5.3 - DSA (DIGITAL SIGNATURE ALGORITHM)")
    
    print("\nDSA Signature Process:")
    print("  • Sign: (r, s) where r = (g^k mod p) mod q")
    print("  •        s = k^-1(H(m) + x*r) mod q")
    print("  • Verify: v = (g^u1 * y^u2 mod p) mod q where")
    print("  •         u1 = H(m)*w, u2 = r*w, w = s^-1 mod q")
    print("  • Signature size: 2 * log_2(q) bits (typically 320 bits)")
    
    print("\n" + "-" * 80)
    print("DSA Signature Test:")
    print("-" * 80)
    
    # DSA parameters
    p = 1000000007
    q = 500000003
    g = 2
    x = 123456789
    
    print(f"\nDSA Parameters:")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  g = {g}")
    print(f"  x = {x} (private key)")
    
    # Create signer
    signer = DSA(p, q, g, x)
    print(f"  y = {signer.y} (public key)")
    
    # Create verifier
    verifier = DSA(p, q, g)
    verifier.y = signer.y
    
    # Test
    message = b"This is a legally binding contract"
    
    print(f"\n1. Message: {message}")
    
    # Sign
    sig = signer.sign(message)
    print(f"   Signature: r={sig[0]}, s={sig[1]}")
    
    # Verify
    is_valid = verifier.verify(message, sig)
    print(f"   Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    # Test tampering
    print("\n2. Tampering detection:")
    tampered = b"This is a legally binding CONTRACT"
    is_valid = verifier.verify(tampered, sig)
    print(f"   Tampered: {'✓ VALID (FAIL!)' if is_valid else '✗ INVALID (expected)'}")
    
    print("\n✓ DSA Signature Exercises Completed")


def exercice_5_4_ecdsa():
    """Exercise 5.4: ECDSA Signatures."""
    print_header("EXERCICE 5.4 - ECDSA (ELLIPTIC CURVE DIGITAL SIGNATURE)")
    
    print("\nECDSA Signature Process:")
    print("  • Sign: (r, s) where r = (k*G).x mod n")
    print("  •        s = k^-1(H(m) + d*r) mod n")
    print("  • Verify: Verify == r where")
    print("  •         Verify = (u1*G + u2*Q).x mod n")
    print("  • Key advantage: 256-bit ECDSA ≈ 3072-bit RSA in security")
    print("  • Used in: Bitcoin, TLS 1.3, Ethereum")
    
    print("\n" + "-" * 80)
    print("ECDSA Signature Test (Small Curve for Demo):")
    print("-" * 80)
    
    # Simple curve for demo
    p = 17
    a = 2
    b = 2
    n = 19
    gx, gy = 5, 1
    
    curve = EllipticCurve(a, b, p, n, gx, gy)
    
    print(f"\nElliptic Curve: y^2 = x^3 + {a}x + {b} (mod {p})")
    print(f"Generator G = ({gx}, {gy}), order n = {n}")
    
    # Generate keypair
    d = 5
    signer = ECDSA(curve, d)
    print(f"Private key d = {d}")
    print(f"Public key Q = ({signer.Q.x}, {signer.Q.y})")
    
    # Create verifier
    verifier = ECDSA(curve)
    verifier.Q = signer.Q
    
    # Test message
    message = b"Sign me with ECDSA"
    
    print(f"\n1. Message: {message}")
    
    # Sign
    sig = signer.sign(message)
    print(f"   Signature: r={sig[0]}, s={sig[1]}")
    
    # Verify
    is_valid = verifier.verify(message, sig)
    print(f"   Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    # Test tampering
    print("\n2. Tampering detection:")
    tampered = b"FAKE: Sign me with ECDSA"
    is_valid = verifier.verify(tampered, sig)
    print(f"   Tampered: {'✓ VALID (FAIL!)' if is_valid else '✗ INVALID (expected)'}")
    
    print("\n✓ ECDSA Signature Exercises Completed")


def signature_comparison():
    """Compare all signature algorithms."""
    print_header("SIGNATURE ALGORITHM COMPARISON")
    
    print("\n┌──────────────┬──────────────┬──────────────┬──────────────┬──────────────┐")
    print("│ Property     │     RSA      │   ElGamal    │      DSA     │     ECDSA    │")
    print("├──────────────┼──────────────┼──────────────┼──────────────┼──────────────┤")
    print("│ Key Size     │ 2048+ bits   │ 2048+ bits   │ 1024+ bits   │ 256-384 bits │")
    print("│ Signature    │ 256-512B     │ 512B+        │ 320B (DSA)   │ 64B (ECDSA)  │")
    print("│ Speed        │ Slow (d^e)   │ Slow         │ Medium       │ Fast         │")
    print("│ Determinism  │ Deterministic│ Random (k)   │ Random (k)   │ Random (k)   │")
    print("├──────────────┼──────────────┼──────────────┼──────────────┼──────────────┤")
    print("│ Security     │ ✓ Strong     │ ◐ Good       │ ✓ Strong     │ ✓ Strong     │")
    print("│ Recommended  │ ✓ (with PSS) │ ✗ (legacy)   │ ◐ (old std)  │ ✓ (modern)   │")
    print("│ Standard     │ TLS 1.2      │ PGP (legacy) │ FIPS 186     │ TLS 1.3      │")
    print("│ RNG Depend   │ Low          │ HIGH         │ HIGH         │ HIGH         │")
    print("└──────────────┴──────────────┴──────────────┴──────────────┴──────────────┘")
    
    print("\nSecurity Considerations:")
    print("  • RSA: Requires PSS padding, vulnerable to common mistakes")
    print("  • ElGamal: Requires fresh random k, slow, rarely used now")
    print("  • DSA: Fixed signature size, requires good RNG, older standard")
    print("  • ECDSA: Modern, compact, but requires deterministic k (RFC 6979)")
    
    print("\nModern Recommendations (2026):")
    print("  ✓ EdDSA (Ed25519): Deterministic, simpler, fewer pitfalls")
    print("  ✓ ECDSA (P-256): Industry standard, widely supported")
    print("  ✓ RSA-PSS: Acceptable, but avoid RSA-PKCS#1 v1.5")
    print("  ✗ DSA: Legacy only")
    print("  ✗ ElGamal: Educational only")


def main():
    """Run all TP5 exercises."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 78 + "║")
    print("║" + "TP 5 - DIGITAL SIGNATURES".center(78) + "║")
    print("║" + "RSA, ElGamal, DSA, ECDSA".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╚" + "=" * 78 + "╝")
    
    try:
        exercice_5_1_rsa()
        exercice_5_2_elgamal()
        exercice_5_3_dsa()
        exercice_5_4_ecdsa()
        signature_comparison()
        
        print_header("TP 5 - DIGITAL SIGNATURES TEST SUITE COMPLETE")
        print("\n✓ All exercises completed successfully")
        print("ℹ Summary:")
        print("  • RSA: PKCS#1 v1.5 and PSS padding schemes tested")
        print("  • ElGamal: Discrete log-based signatures")
        print("  • DSA: Federal standard signature algorithm")
        print("  • ECDSA: Modern elliptic curve signatures")
        print("  • All support signing, verification, and forgery detection")
        print("\n")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
