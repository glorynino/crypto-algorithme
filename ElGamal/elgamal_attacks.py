"""
ElGamal Vulnerabilities and Attacks
Homomorphic property abuse, small subgroup attacks, re-encryption attacks
"""

from elgamal import ElGamalParams, ElGamalKey, elgamal_encrypt, elgamal_decrypt


def elgamal_homomorphic_attack():
    """
    ElGamal Homomorphic Property Attack
    E(m1) * E(m2) = E(m1 * m2 mod p)
    Can forge and manipulate ciphertexts
    """
    print("\n" + "=" * 70)
    print("ELGAMAL HOMOMORPHIC PROPERTY ATTACK")
    print("=" * 70)
    
    print(f"""\n
ElGamal encryption structure:
  Ciphertext: (c1, c2) where c1 = g^k, c2 = h^k * m
  
Homomorphic property:
  E(m1) = (c1_1, c2_1) where c2_1 = h^k1 * m1
  E(m2) = (c1_2, c2_2) where c2_2 = h^k2 * m2
  
  E(m1) * E(m2) = (c1_1 * c1_2, c2_1 * c2_2)
                = (g^(k1+k2), h^(k1+k2) * m1 * m2)
                = E(m1 * m2)
  
Attack Applications:
  
  1. Chosen Plaintext Attack:
     - Attacker queries encryption oracle for m1, m2, ...
     - Computes: c' = E(m1) * E(m2) = E(m1 * m2)
     - Can generate ciphertexts for plaintexts never queried!
  
  2. Signature Forgery (if used for signatures):
     - Attacker can forge valid signatures without key
     - Multiply/modulate existing signatures
  
  3. Vote Manipulation (in voting systems):
     - Multiply vote ciphertexts to change totals
     - Without breaking encryption
  
Defense:
  • Add authentication (sign ciphertexts)
  • Use randomization in decryption (check plaintext likely)
  • Use IND-CCA2 secure encryption (padding + authentication)
  • Add redundancy: hash plaintext + append it
  • Use proven secure constructions (not textbook)
    """)


def small_subgroup_attack_elgamal():
    """
    Small Subgroup Confinement Attack on ElGamal
    If generator g has small order, plaintext leaks
    """
    print("\n" + "=" * 70)
    print("SMALL SUBGROUP ATTACK ON ELGAMAL")
    print("=" * 70)
    
    print(f"""\n
Scenario: Attacker notices g generates small subgroup
  
Steps:
  1. Attacker finds small factor q of (p-1)
  2. Computes g' = g^((p-1)/q)
  3. g' generates subgroup of order q
  4. Interacts with system using g' instead of g
  5. After decryption, plaintext restricted to [0, q)
  
Information Leakage:
  • Recover plaintext mod q (small value)
  • With multiple subgroups, use CRT
  • Combine to recover plaintext bits
  
Example (p-1 = 2 × 3 × 5 × 7 × 11 × ...):
  • Attack with q=2: learn m mod 2 (LSB)
  • Attack with q=3: learn m mod 3
  • Attack with q=5: learn m mod 5
  • ...
  • CRT: combine to recover m exactly!
  
Defense:
  • Use safe prime: p = 2q + 1 where q is prime
  • Verify order of received values
  • Check: received_value^q ≠ 1 mod p
  • Or use larger p with all large prime factors in p-1
  • Validate that g has order (p-1) or large prime order
    """)


def re_encryption_tracking_attack():
    """
    Re-encryption Tracking Attack
    Attacker can identify if plaintext was re-encrypted
    """
    print("\n" + "=" * 70)
    print("RE-ENCRYPTION TRACKING ATTACK")
    print("=" * 70)
    
    print(f"""\n
Scenario: Proxy using ElGamal for re-encryption
  e.g., encrypts under Alice's key, then under Bob's key
  
Attack (Proxy Re-encryption vulnerability):
  
  1. Original ciphertext for Alice:
     c = (g^k, h_A^k * m)
  
  2. Proxy re-encrypts for Bob (without seeing m):
     c' = (g^k', h_B^k' * c₂ / (h_A^k * h_A^(-k)))
  
  3. Problem: Re-encryption is malleable!
     Attacker can detect re-encryption by checking:
     c'₁ / c₁ = g^(k'-k) (ratio reveals pattern)
  
  4. Information leakage:
     - Can track messages through proxies
     - Distinguish re-encrypted from freshly encrypted
     - Violates privacy in anonymous systems
  
Defense:
  • Use PRE-secure construction (proved resistant)
  • Blind the transformation
  • Add randomization to re-encryption
  • Use ECIES or hybrid schemes
    """)


def passive_key_recovery_via_subgroup():
    """
    Passive Key Recovery via Small Subgroup
    If attacker can force small subgroup values
    """
    print("\n" + "=" * 70)
    print("PASSIVE KEY RECOVERY VIA SUBGROUP CONFINEMENT")
    print("=" * 70)
    
    print(f"""\n
Advanced Attack: Subgroup Confinement + CRT
  
Precondition: p-1 = q1 × q2 × q3 × ... (many small primes)
  
Setup:
  • Alice uses normal DH/ElGamal with generator g
  • g should generate full group of order p-1
  • But what if g only generates subgroup?
  
Attack Steps:
  1. For each small prime factor qi:
     - Compute g_i = g^((p-1)/qi)
     - g_i generates subgroup of order qi
     - Send message encrypted with g_i
     - Observe Alice's response (or leaked timing)
     - Learn x mod qi (Alice's private key mod qi)
  
  2. Repeat for all small factors
  
  3. Use Chinese Remainder Theorem:
     - x ≡ a1 (mod q1)
     - x ≡ a2 (mod q2)
     - ...
     - Recover x mod (q1 × q2 × ...)
  
  If q1 × q2 × ... > 2^k for target k bits:
     → Completely determine x
  
Example:
  p = 1000000007
  p-1 = 2 × 3 × 166666668  (approximately, for demo)
  
  Attacker gets:
  - x mod 2 (0 or 1)
  - x mod 3 (0, 1, or 2)
  - x mod 166666668
  
  Product: 2 × 3 × 166666668 = 1000000012 > 2^30
  → Complete key recovery!
  
Defense (RFC 7919 Safe Primes):
  • p = 2q + 1 where q is prime (safe prime)
  • Then p-1 = 2 × q (only 2 and large prime)
  • g^2 ≠ 1 ensures g generates full group
  • Subgroup confinement attacks impossible
    """)


def distinguishing_attack_semantics():
    """
    Distinguishing Attack: ElGamal lacks semantic security
    """
    print("\n" + "=" * 70)
    print("DISTINGUISHING ATTACK: LACK OF SEMANTIC SECURITY")
    print("=" * 70)
    
    print(f"""\n
Problem: Textbook ElGamal is deterministic-like in nature
  
Attack Setup:
  1. Attacker has two candidate plaintexts: m0, m1
  2. Challenger encrypts b ∈ {0,1} under public key
  3. Attacker goal: guess which was encrypted
  
Distinguishing Approach:
  • ElGamal leaks whether plaintext is quadratic residue
  • m is QR mod p ⟺ m^((p-1)/2) ≡ 1 (mod p)
  • Ciphertext (c1, c2) is QR ⟺ m is QR
  • Attacker can check: c2^((p-1)/2) mod p
  
Attack Steps:
  1. Choose m0 = quadratic residue (e.g., 2^2)
     Choose m1 = non-residue (e.g., 3)
  2. Receive ciphertext (c1, c2)
  3. Compute c2^((p-1)/2) mod p
  4. If ≡ 1: guess m0
     If ≡ p-1: guess m1
  5. Win with >50% probability
  
Why it works:
  • c2 = h^k * m = g^(xk) * m mod p
  • Legendre symbol: (c2) = (g^(xk) * m)
  •              = (g^(xk)) * (m)
  •              = 1 (g^(xk) always QR if q even)
  •              = (m) × deterministic_factor
  
Real Attack (in practice):
  • Attacker doesn't know candidate values
  • But can distinguish ciphertexts
  • Leaks information about plaintext
  
Defense:
  • Use ECIES (Elliptic Curve)
  • Add random padding (randomized encoding)
  • Use IND-CCA2 secure construction
  • Hash-based schemes (provably secure padding)
    """)


def main():
    """Run all ElGamal attack demonstrations"""
    
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "ELGAMAL VULNERABILITIES & ATTACKS" + " " * 19 + "║")
    print("╚" + "═" * 68 + "╝")
    
    elgamal_homomorphic_attack()
    small_subgroup_attack_elgamal()
    re_encryption_tracking_attack()
    passive_key_recovery_via_subgroup()
    distinguishing_attack_semantics()
    
    print("\n" + "═" * 70)
    print("LESSONS FOR SECURE ELGAMAL:")
    print("═" * 70)
    print("""
1. Parameter Selection:
   • RFC 7919/RFC 3526 group (safe primes)
   • Or Schnorr group with certified generator
   • p-1 must have large prime factor
   
2. Implementation:
   • Add integrity check (MAC or signature)
   • Use deterministic padding or randomization
   • Hash plaintext before encryption
   • Never use raw ElGamal
   
3. Protocols:
   • Use DHIES (DH Integrated Encryption Scheme)
   • Or ECIES (Elliptic Curve variant)
   • Both are CCA2-secure with proper setup
   
4. Production Use:
   • Don't use ElGamal directly
   • Use ECIES in modern protocols
   • PQC alternatives for quantum-safe
   
5. Proxy Re-encryption (if applicable):
   • Use CPA-secure transformation
   • Or Byzantine-robust mechanisms
   • Verify integrity of transformation
""")
    print("═" * 70 + "\n")


if __name__ == "__main__":
    main()
