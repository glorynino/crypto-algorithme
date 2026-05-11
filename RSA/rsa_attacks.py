"""
RSA Vulnerabilities and Attacks
Textbook RSA attacks, small e, common modulus, Bleichenbacher oracle attack, signature forgery
"""

import random
from math import gcd
from functools import reduce


def small_exponent_attack(n, e, ciphertext):
    """
    Small Exponent Attack: If e is small and plaintext small, 
    m^e < n means ciphertext is NOT reduced modulo n
    Can recover by taking eth root
    """
    print("\n" + "=" * 70)
    print("SMALL EXPONENT ATTACK (e=3)")
    print("=" * 70)
    
    print(f"\nTarget RSA public key: (n, e)")
    print(f"  n = {n}")
    print(f"  e = {e} (very small)\n")
    
    print(f"Attacker intercepts ciphertext: c = {ciphertext}\n")
    
    print(f"Attack: If m^e < n, then c = m^e (NO modular reduction)")
    print(f"  Therefore: m = ∛c (cube root)\n")
    
    # Try to compute eth root
    # For small e, can use binary search or Newton's method
    m_approx = int(ciphertext ** (1.0 / e))
    
    # Verify and refine
    for candidate in range(m_approx - 2, m_approx + 3):
        if candidate ** e == ciphertext:
            print(f"✓ Successfully recovered plaintext: m = {candidate}")
            print(f"  Verification: {candidate}^{e} = {candidate ** e} ✓\n")
            return candidate
    
    print(f"Plaintext too large, fell in modular reduction:")
    print(f"  m^e ≥ n, so c ≡ m^e (mod n) but ≠ m^e\n")
    return None


def common_modulus_attack(n, e1, e2, c1, c2):
    """
    Common Modulus Attack: If same n used with different e1, e2
    and gcd(e1, e2) = 1, can recover plaintext WITHOUT private key
    """
    print("\n" + "=" * 70)
    print("COMMON MODULUS ATTACK")
    print("=" * 70)
    
    print(f"\nScenario: Same message m encrypted twice with different exponents")
    print(f"  (n, e1) and (n, e2) share same modulus n\n")
    
    print(f"Public keys:")
    print(f"  Key 1: (n, e1={e1})")
    print(f"  Key 2: (n, e2={e2})")
    print(f"  Modulus: n = {n}\n")
    
    print(f"Attacker has:")
    print(f"  c1 = m^e1 mod n = {c1}")
    print(f"  c2 = m^e2 mod n = {c2}\n")
    
    # Check gcd(e1, e2)
    g = gcd(e1, e2)
    print(f"Analysis: gcd(e1, e2) = gcd({e1}, {e2}) = {g}")
    
    if g != 1:
        print(f"gcd ≠ 1, attack doesn't apply\n")
        return None
    
    print(f"gcd = 1, attack WORKS!\n")
    
    # Find x, y such that e1*x + e2*y = 1
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    
    _, x, y = extended_gcd(e1, e2)
    
    print(f"Extended GCD: {e1}·{x} + {e2}·{y} = 1\n")
    
    # Compute m = c1^x · c2^y mod n
    if x < 0:
        # c1^x = (c1^-1)^|x|
        c1_inv = pow(c1, n - 2, n)  # Using FLT: a^-1 ≡ a^(n-2) mod n
        m = pow(c1_inv, -x, n)
    else:
        m = pow(c1, x, n)
    
    if y < 0:
        c2_inv = pow(c2, n - 2, n)
        m = (m * pow(c2_inv, -y, n)) % n
    else:
        m = (m * pow(c2, y, n)) % n
    
    print(f"Computation:")
    print(f"  m = c1^{x} · c2^{y} mod n")
    print(f"  m = {c1}^{x} · {c2}^{y} mod {n}")
    print(f"  m = {m}\n")
    
    print(f"✓ Recovered plaintext WITHOUT private key!")
    return m


def related_message_attack(n, e, c1, c2, k):
    """
    Related Message Attack: If attacker knows m2 = k·m1
    and has both ciphertexts, can recover m1
    """
    print("\n" + "=" * 70)
    print("RELATED MESSAGE ATTACK")
    print("=" * 70)
    
    print(f"\nScenario: Attacker knows plaintexts are related")
    print(f"  m2 = k·m1 (messages differ by known constant k)\n")
    
    print(f"  c1 = m1^e mod n = {c1}")
    print(f"  c2 = (k·m1)^e mod n = k^e·m1^e mod n = {c2}")
    print(f"  k = {k}\n")
    
    # Compute (c2 / (k^e mod n)) = c1
    k_e = pow(k, e, n)
    ratio = (c2 * pow(k_e, n - 2, n)) % n  # Divide by k_e
    
    valid = (ratio == c1)
    print(f"Verification: c2 / k^e = c1? {valid}\n")
    
    if valid:
        print(f"✓ Can use this to forge signatures or recover keys in specific scenarios")


def chinese_remainder_theorem(residues):
    """CRT helper"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y
    
    def mod_inverse(a, m):
        gcd_val, x, _ = extended_gcd(a % m, m)
        if gcd_val != 1:
            return None
        return (x % m + m) % m
    
    total = 0
    prod = 1
    for _, m_i in residues:
        prod *= m_i
    
    for a_i, m_i in residues:
        p = prod // m_i
        total += a_i * mod_inverse(p, m_i) * p
    
    return total % prod


def textbook_rsa_homomorphic_property():
    """
    Demonstrate RSA homomorphic property
    E(m1) × E(m2) = E(m1 × m2)
    """
    print("\n" + "=" * 70)
    print("TEXTBOOK RSA: HOMOMORPHIC PROPERTY VULNERABILITY")
    print("=" * 70)
    
    print(f"\nRSA Encryption: E(m) = m^e mod n\n")
    
    print("Property: E(m1) · E(m2) ≡ E(m1 · m2) (mod n)\n")
    
    print("Attack application:")
    print("  1. Attacker has ciphertext c = m^e")
    print("  2. Attacker multiplies: c · 2^e mod n = (2m)^e mod n")
    print("  3. Sends to oracle: 'Decrypt for me'")
    print("  4. Gets back: 2m")
    print("  5. Divides by 2: m recovered\n")
    
    print("This is basis for Bleichenbacher attack and lunchbox attacks")


def padding_oracle_attack_concept():
    """
    Padding Oracle Attack Concept
    If server says 'invalid padding', attacker learns ciphertext bits
    """
    print("\n" + "=" * 70)
    print("PADDING ORACLE ATTACK CONCEPT")
    print("=" * 70)
    
    print(f"""
PKCS#1 v1.5 Padding:
  Ciphertext decrypts to: 0x00 0x02 [random non-zero bytes] 0x00 [message]
  Server checks: "Is it 0x00 0x02 ... 0x00?"
  
Oracle Attack (Bleichenbacher):
  1. Attacker has c = m^e mod n (encrypted message)
  2. Attacker sends c' = (s^e · c) mod n for various s
  3. Server decrypts c' and checks padding
  4. If padding valid: 2ms mod n is in valid range
  5. Accumulate constraints from many s values
  6. After O(log n) oracle calls, narrow down m
  
Defenses:
  • Use OAEP padding (modern, provably secure)
  • Don't leak padding information via timing/error messages
  • Use authenticated encryption (RSA should only be for signatures)
    """)


def textbook_rsa_signature_forgery():
    """
    Textbook RSA Signature Attacks
    """
    print("\n" + "=" * 70)
    print("TEXTBOOK RSA SIGNATURE ATTACKS")
    print("=" * 70)
    
    print(f"""\n
Attack 1: No Message Recovery Protection
  • Signature: S = m^d mod n
  • Attacker computes: m' = S · S mod n = m^2d mod n
  • This is a valid signature for m^2!
  
Attack 2: Multiplicative Property
  • Has (m1, s1) where s1 = sig(m1)
  • Computes: s'= s1 · s2 where s2 = sig(m2)
  • Then: s' is valid signature for (m1 · m2 mod n)!
  
Attack 3: No Randomness in Signature
  • Same message always produces same signature
  • Allows replay attacks
  
Attack 4: Padding Weakness in PSS
  • Old PKCS#1 v1.5 signature padding forges
  • Attacker can craft fakeable bits
  
Defenses:
  • Always use hash: sig = H(m)^d mod n
  • Use PSS padding (probabilistic)
  • Include random nonce for freshness
  • Use ECDSA or RSA-PSS in practice
    """)


def low_exponent_broadcast_attack():
    """
    Low Exponent Broadcast Attack (Hastad)
    If e=3 and same message sent to 3 different recipients
    Can recover plaintext via CRT
    """
    print("\n" + "=" * 70)
    print("LOW EXPONENT BROADCAST ATTACK (Hastad's Attack)")
    print("=" * 70)
    
    print(f"""\n
Scenario: 
  • Server broadcasts message m to 3+ parties
  • Each has own RSA keypair (n_i, 3)
  • Attacker intercepts all ciphertexts c_i
  
Attack:
  • c1 = m^3 mod n1
  • c2 = m^3 mod n2  
  • c3 = m^3 mod n3
  
  • Use CRT to compute C = m^3 mod (n1·n2·n3)
  • Since m^3 < n1·n2·n3 (all ni >> m), C = m^3 exactly
  • Take cube root: m = ∛C
  
Example numbers:
  If m = 1000 (12 bits)
  n1, n2, n3 each ~1024 bits
  n1·n2·n3 = 3072 bits
  m^3 = 10^9 bits < 3072 bits space
  
Countermeasures:
  • Use e = 65537 (larger exponent)
  • Add random padding to message
  • Use semantic security (like OAEP)
    """)


def main():
    """Run all RSA attack demonstrations"""
    
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + " " * 18 + "RSA VULNERABILITIES & ATTACKS" + " " * 20 + "║")
    print("╚" + "═" * 68 + "╝")
    
    # Demo 1: Small exponent
    n_small = 3233  # 61 × 53
    e_small = 3
    m_small = 42
    c_small = pow(m_small, e_small, n_small)
    small_exponent_attack(n_small, e_small, c_small)
    
    # Demo 2: Common modulus
    n_cm = 3233
    e1 = 17
    e2 = 61  # gcd(17, 61) = 1
    m = 100
    c1 = pow(m, e1, n_cm)
    c2 = pow(m, e2, n_cm)
    common_modulus_attack(n_cm, e1, e2, c1, c2)
    
    # Demo 3: Related messages
    e = 65537
    n = 3233
    m1 = 50
    k = 2
    c1 = pow(m1, e, n)
    c2 = pow((k * m1) % n, e, n)
    related_message_attack(n, e, c1, c2, k)
    
    # Demo 4: Homomorphic property
    textbook_rsa_homomorphic_property()
    
    # Demo 5: Padding oracle
    padding_oracle_attack_concept()
    
    # Demo 6: Signature attacks
    textbook_rsa_signature_forgery()
    
    # Demo 7: Hastad attack
    low_exponent_broadcast_attack()
    
    print("\n" + "═" * 70)
    print("LESSONS FOR SECURE RSA:")
    print("═" * 70)
    print("""
1. Key Generation:
   • Use e = 65537 (standard), not small values like 3
   • Use strong primes (safe primes p, q)
   • Key size: 2048-bit minimum, 4096-bit recommended
   
2. Encryption:
   • ALWAYS use OAEP padding
   • NEVER use textbook RSA
   • Implement constant-time to resist timing attacks
   
3. Signatures:
   • ALWAYS hash message before signing
   • Use PSS padding scheme
   • Verify message before trusting signature
   
4. Implementation:
   • Use vetted libraries (not homework implementations)
   • Validate all inputs
   • Protect private keys strictly
   
Modern Usage (TLS):
   • RSA only for key encapsulation (hybrid with KEM)
   • Or signatures in certificates
   • Prefer ECDSA/EdDSA for new protocols
   • Or post-quantum resistant algorithms
""")
    print("═" * 70 + "\n")


if __name__ == "__main__":
    main()
