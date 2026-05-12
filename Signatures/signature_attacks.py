"""
Digital Signature Attacks and Vulnerabilities
Demonstrates practical attacks on signature schemes
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


def ecdsa_nonce_reuse_attack(msg1, msg2, sig1, sig2, n):
    """
    Recover private key from two ECDSA signatures with same nonce.
    
    If same k used:
      s1 = k^-1(z1 + d*r) mod n
      s2 = k^-1(z2 + d*r) mod n
    
    Then:
      k = (z1 - z2) / (s1 - s2) mod n
      d = r^-1 * (k*s1 - z1) mod n
    """
    r1, s1_val = sig1
    r2, s2_val = sig2
    
    # If r values differ, nonce wasn't reused
    if r1 != r2:
        return None, "Different r values - nonce wasn't reused"
    
    r = r1
    
    # Hash messages
    z1 = int.from_bytes(hashlib.sha256(msg1).digest(), 'big') % n
    z2 = int.from_bytes(hashlib.sha256(msg2).digest(), 'big') % n
    
    # Recover k
    numerator = (z1 - z2) % n
    denominator = (s1_val - s2_val) % n
    
    try:
        den_inv = mod_inverse(denominator, n)
    except ValueError:
        return None, "Cannot invert denominator"
    
    k = (numerator * den_inv) % n
    
    # Recover private key d
    r_inv = mod_inverse(r, n)
    d = (r_inv * (k * s1_val - z1)) % n
    
    return d, f"Recovered d={d} from nonce reuse"


def small_subgroup_attack():
    """
    Demonstrate small subgroup attack on DSA-like schemes.
    If q (subgroup order) is small, attacker can forge signatures.
    """
    print("\n" + "=" * 70)
    print("SMALL SUBGROUP ATTACK (DSA/ECDSA)")
    print("=" * 70)
    
    # Vulnerable parameters (intentionally small for demo)
    p = 2 * 101 + 1  # p = 203, prime
    q = 101          # small prime
    
    print(f"\nVulnerable parameters:")
    print(f"  p = {p} (prime)")
    print(f"  q = {q} (small prime divisor)")
    
    # Attacker knows q is small
    print(f"\nAttacker strategy:")
    print(f"  1. Brute force compute d mod q (only {q} possibilities)")
    print(f"  2. Sign messages on subgroup of size {q}")
    print(f"  3. Forge signatures without knowing d mod (p-1)")
    
    return p, q


def textbook_rsa_signature_attack():
    """
    Demonstrate textbook RSA signature attacks.
    Attack: E(m1) * E(m2) = E(m1 * m2)
    """
    print("\n" + "=" * 70)
    print("TEXTBOOK RSA SIGNATURE ATTACKS")
    print("=" * 70)
    
    print("\nVulnerability: Multiplicative property")
    print("If attacker has σ1 = Sign(m1) and σ2 = Sign(m2)")
    print("Then σ' = σ1 * σ2 is valid signature for m1*m2")
    
    print("\nExample attack:")
    print("  1. Attacker intercepts signature σ = Sign(contract)")
    print("  2. Computes σ' = σ * r for some r (forge new signature)")
    print("  3. Without key, attacker creates valid signature for document*r")
    
    print("\nDefense: Use RSA-PSS or PSS padding")
    print("  • Add randomization to prevent multiplicative attacks")
    print("  • Verify message matches expected format")


def length_extension_attack_demo():
    """
    Demonstrate length extension attack on hash-based signatures.
    Only applies to MD5/SHA-1 Merkle-Damgård, NOT SHA-256 (fixed in SHA-2).
    """
    print("\n" + "=" * 70)
    print("LENGTH EXTENSION ATTACK (Hash-based Signatures)")
    print("=" * 70)
    
    print("\nVulnerability (MD5/SHA-1 only):")
    print("  If attacker knows H(secret || message)")
    print("  Can compute H(secret || message || additional_data)")
    print("  WITHOUT knowing the secret")
    
    print("\nAttack scenario:")
    print("  1. Alice signs: σ = Sign(secret || 'Transfer 100 to Bob')")
    print("  2. Attacker intercepts signature")
    print("  3. Computes: H' = Hash(secret || 'Transfer...' || padding || '1000')")
    print("  4. Tricks Bob with forged signature")
    
    print("\nDefense:")
    print("  ✓ SHA-256+ (not vulnerable to length extension)")
    print("  ✓ Use HMAC instead of bare hash")
    print("  ✓ Sign(HMAC(message)) instead of Sign(Hash(message))")


def replay_attack_demo():
    """
    Demonstrate replay attack on signatures.
    """
    print("\n" + "=" * 70)
    print("REPLAY ATTACK (Digital Signatures)")
    print("=" * 70)
    
    print("\nVulnerability: Signatures don't include context")
    
    print("\nAttack scenario (Bitcoin-like):")
    print("  1. Alice: 'Transfer 1 BTC to attacker' (signed)")
    print("  2. Attacker intercepts transaction with valid signature")
    print("  3. Attacker: Rebroadcasts SAME signature multiple times")
    print("  4. Result: 1 transaction becomes 10 transfers!")
    
    print("\nDefense:")
    print("  ✓ Include nonce in signed message (prevents replays)")
    print("  ✓ Sign(message || nonce || timestamp)")
    print("  ✓ Ledger/blockchain timestamps (cumulative)")
    print("  ✓ Track consumed signatures")


def key_reuse_risk():
    """
    Demonstrate risks of key reuse across different schemes.
    """
    print("\n" + "=" * 70)
    print("KEY REUSE RISKS")
    print("=" * 70)
    
    print("\nProblem: Using same key for multiple purposes")
    
    print("\nScenario:")
    print("  Alice uses same private key (d) for:")
    print("  • ECDSA signatures (deterministic k derivation)")
    print("  • ElGamal encryption (requires fresh randomness)")
    print("  • Key agreement (static DH)")
    
    print("\nRisks:")
    print("  ✗ Weak RNG in one scheme exposes key in all")
    print("  ✗ Timing attacks correlate across schemes")
    print("  ✗ ECDSA/DSA k reuse breaks everything")
    
    print("\nDefense:")
    print("  ✓ Use separate keys for signing vs encryption")
    print("  ✓ Use separate keys per purpose (TLS: enc key, sign key)")
    print("  ✓ Rotation strategy (key versioning)")


if __name__ == "__main__":
    print("╔" + "=" * 68 + "╗")
    print("║" + "DIGITAL SIGNATURE ATTACKS & VULNERABILITIES".center(68) + "║")
    print("╚" + "=" * 68 + "╝")
    
    small_subgroup_attack()
    textbook_rsa_signature_attack()
    length_extension_attack_demo()
    replay_attack_demo()
    key_reuse_risk()
    
    print("\n" + "=" * 70)
    print("✓ All attacks demonstrated")
    print("=" * 70)
    
    print("\nKey Recommendations:")
    print("  1. Use RSA-PSS or deterministic ECDSA (RFC 6979)")
    print("  2. Use EdDSA (Ed25519) for simplicity and security")
    print("  3. Include nonces/timestamps in signed messages")
    print("  4. Use separate keys for different purposes")
    print("  5. Use strong RNG for DSA/ECDSA nonces")
