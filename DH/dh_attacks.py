"""
Diffie-Hellman Vulnerabilities and Attacks
Small subgroup attacks, MITM, parameter validation, weak prime selection
"""

import random
from math import gcd
from dh import DH, DH_Parameters


def pohlig_hellman_attack(p, g, public_key, small_factors):
    """
    Pohlig-Hellman attack: Factor p-1 into small primes
    Recover private key modulo each small prime, then CRT to recover full key
    Requires: p-1 has only small prime factors
    """
    print("\n" + "=" * 70)
    print("POHLIG-HELLMAN ATTACK: Small Factor Exploitation")
    print("=" * 70)
    
    print(f"\nAttacker knows:")
    print(f"  Public parameters: p={p}, g={g}")
    print(f"  Bob's public key: B = g^b mod p = {public_key}\n")
    
    # Factor p-1 into small primes
    print(f"Factorization of p-1:")
    factors = dict(small_factors)
    for prime, count in sorted(factors.items()):
        print(f"  {prime}^{count}")
    
    print(f"\nAttacking using small factors:")
    
    residues = []  # (b mod prime_i^count_i) for each factor
    
    for prime, count in small_factors:
        prime_power = prime ** count
        order = (p - 1) // prime_power
        
        # Compute g^order mod p (element of order prime_power in subgroup)
        h = pow(g, order, p)
        # Compute B^order mod p
        z = pow(public_key, order, p)
        
        # Discrete log: find b_i such that h^b_i ≡ z (mod p)
        # Using brute force for small prime_power
        b_i = 0
        for x in range(prime_power):
            if pow(h, x, p) == z:
                b_i = x
                break
        
        residues.append((b_i, prime_power))
        print(f"  b ≡ {b_i} (mod {prime_power})")
    
    # Chinese Remainder Theorem
    print(f"\nCombining using CRT:")
    recovered_b = chinese_remainder_theorem(residues)
    
    print(f"  Recovered private key (mod product of factors): {recovered_b}")
    print(f"  Note: This narrows down from 2^{p.bit_length()} to ~2^{sum(f[0].bit_length() * f[1] for f in small_factors) // len(small_factors)}")
    
    return recovered_b


def small_subgroup_attack(p, g, public_key):
    """
    Small Subgroup Attack (Lim-Lee)
    If g generates small-order subgroup, attacker learns secret mod subgroup order
    """
    print("\n" + "=" * 70)
    print("SMALL SUBGROUP ATTACK: Order Confusion")
    print("=" * 70)
    
    print(f"\nAttacker analyzes order of g:")
    print(f"  g = {g}")
    
    # Check if g has small order
    for test_order in [2, 3, 5, 7, 11, 13]:
        if pow(g, test_order, p) == 1:
            print(f"  ✓ Found: g^{test_order} ≡ 1 (mod p)")
            print(f"  Order of g divides {test_order}\n")
            
            # Recover secret mod test_order
            print(f"Attacking with small order {test_order}:")
            print(f"  Bob's public key: B = g^b mod p = {public_key}")
            
            # Brute force b mod test_order
            for candidate in range(test_order):
                if pow(g, candidate, p) == public_key:
                    print(f"  ✓ Recovered: b ≡ {candidate} (mod {test_order})")
                    return candidate
    
    print(f"  No small order found (proper parameter selection)")
    return None


def mitm_attack_unauth_dh():
    """
    Man-in-the-Middle Attack on Anonymous DH
    Shows why authentication is critical
    """
    print("\n" + "=" * 70)
    print("MAN-IN-THE-MIDDLE (MITM) ATTACK: Authentication Gap")
    print("=" * 70)
    
    print("\nScenario:")
    print("  Alice and Bob want to establish shared secret over public channel")
    print("  Eve sits in the middle without authentication\n")
    
    # Setup
    params = DH_Parameters(p=23, g=5)  # Small primes for demo
    
    print("1. NORMAL (Secure with Authentication):")
    alice_dh = DH(params)
    bob_dh = DH(params)
    
    alice_pub = alice_dh.get_public_key()
    bob_pub = bob_dh.get_public_key()
    
    print(f"   Alice → Bob: A = {alice_pub}")
    print(f"   Bob → Alice: B = {bob_pub}")
    
    shared_ab = alice_dh.compute_shared_secret(bob_pub)
    shared_ba = bob_dh.compute_shared_secret(alice_pub)
    
    print(f"   Alice computes: K_AB = {shared_ab}")
    print(f"   Bob computes:   K_AB = {shared_ba}")
    print(f"   ✓ Match: {shared_ab == shared_ba}\n")
    
    print("2. MITM ATTACK (No Authentication):")
    print("   Eve intercepts and impersonates both sides\n")
    
    eve_dh = DH(params)
    eve_pub = eve_dh.get_public_key()
    
    print(f"   Alice sends A={alice_pub} → Eve")
    print(f"   Eve impersonates Bob, sends E={eve_pub} to Alice")
    print(f"   Bob sends B={bob_pub} → Eve")
    print(f"   Eve impersonates Alice, sends E={eve_pub} to Bob\n")
    
    # Eve computes two shared secrets
    k_alice_eve = eve_dh.compute_shared_secret(alice_pub)
    k_eve_bob = eve_dh.compute_shared_secret(bob_pub)
    
    print(f"   Eve computes:")
    print(f"     K_Alice = {k_alice_eve}")
    print(f"     K_Bob   = {k_eve_bob}")
    print(f"   Eve can now:")
    print(f"     • Decrypt Alice's messages with K_Alice")
    print(f"     • Re-encrypt with K_Bob for Bob (or modify)")
    print(f"     • Do the reverse for Bob's messages\n")
    
    print("   Result: Complete compromise despite DH working 'correctly'")
    print("   Solution: Use authentication (signs, certificates, etc.)")


def weak_generator_attack(p, g, order, public_key):
    """
    Weak Generator Attack: If g has small order, reveals info
    """
    print("\n" + "=" * 70)
    print("WEAK GENERATOR ATTACK: Order Weakness")
    print("=" * 70)
    
    print(f"\nParameters:")
    print(f"  p = {p}")
    print(f"  g = {g} (generator of subgroup, order = {order})")
    print(f"  Bob's public key B = {public_key}\n")
    
    if order < 2**16:  # Small enough for brute force
        print(f"Order {order} is small - can brute force!\n")
        
        for candidate_b in range(order):
            if pow(g, candidate_b, p) == public_key:
                print(f"✓ Recovered private key (mod {order}): {candidate_b}")
                print(f"  Full key is {candidate_b} + k·{order} for unknown k")
                return candidate_b
    else:
        print(f"Order {order} too large for brute force")
        return None


def passive_eavesdropping_demo():
    """
    Demonstrate why DH is secure against passive eavesdropping
    (but NOT active MITM)
    """
    print("\n" + "=" * 70)
    print("PASSIVE EAVESDROPPING RESISTANCE")
    print("=" * 70)
    
    params = DH_Parameters(p=1000000007, g=2)  # Large prime
    
    print(f"\nParameters:")
    print(f"  p = {params.p} (large prime)")
    print(f"  g = {params.g}\n")
    
    alice_dh = DH(params)
    bob_dh = DH(params)
    
    alice_pub = alice_dh.get_public_key()
    bob_pub = bob_dh.get_public_key()
    
    print("Public information (eavesdropper sees):")
    print(f"  A = g^a mod p = {alice_pub}")
    print(f"  B = g^b mod p = {bob_pub}\n")
    
    shared = alice_dh.compute_shared_secret(bob_pub)
    print(f"Shared secret computed:")
    print(f"  K = g^(ab) mod p = {shared}\n")
    
    print("Why eavesdropper CANNOT compute K:")
    print(f"  1. Knows A (but not a)")
    print(f"  2. Knows B (but not b)")
    print(f"  3. Computing discrete log a from A is hard (p very large)")
    print(f"  4. Computing discrete log b from B is hard (p very large)")
    print(f"  5. No other known way to get g^(ab) mod p from A,B,p,g\n")
    
    print("BUT: Not secure against MITM (see above)")
    print("Solution: Must use authenticated channel or signatures")


def replay_attack_demo():
    """
    Replay Attack: If same ephemeral key reused, can replay messages
    """
    print("\n" + "=" * 70)
    print("REPLAY ATTACK: Key Reuse Problem")
    print("=" * 70)
    
    print("\nScenario: Bob uses same (private key, public key) with different parties\n")
    
    params = DH_Parameters(p=1000000007, g=2)
    
    # Bob (fixed keypair for multiple exchanges)
    bob_dh = DH(params)
    bob_pub = bob_dh.get_public_key()
    bob_priv = bob_dh.private_key
    
    print(f"Bob's long-term keypair:")
    print(f"  b = {bob_priv}")
    print(f"  B = {bob_pub}\n")
    
    # Alice 1
    alice1_dh = DH(params)
    k1 = alice1_dh.compute_shared_secret(bob_pub)
    
    # Alice 2
    alice2_dh = DH(params)
    k2 = alice2_dh.compute_shared_secret(bob_pub)
    
    print(f"Session 1 (with Alice 1):")
    print(f"  Shared Key: {k1}\n")
    
    print(f"Session 2 (with Alice 2):")
    print(f"  Shared Key: {k2}\n")
    
    print(f"✓ Keys different: {k1 != k2} (good)\n")
    
    print("Problem: If Bob reuses SAME ephemeral key:")
    print("  → Both sessions get same shared secret")
    print("  → Can decrypt old messages if one session broken")
    print("\nSolution: Use ephemeral keys (DHE), not static DH")


def parameter_validation_importance():
    """
    Show why parameter validation is critical
    """
    print("\n" + "=" * 70)
    print("PARAMETER VALIDATION: Critical Security Check")
    print("=" * 70)
    
    print("\nValidations required:")
    print("  1. p is prime (usually 2048+ bits)")
    print("  2. p-1 has large prime factor q (Sophie Germain prime or safe prime)")
    print("  3. g is in [2, p-2]")
    print("  4. g^q ≠ 1 (mod p) - g generates large subgroup")
    print("  5. Verify 1 < received_key < p-1\n")
    
    print("Without validation:")
    print("  • Small subgroup attacks leak key bits")
    print("  • Invalid keys compromise forward secrecy")
    print("  • Pohlig-Hellman becomes feasible")
    print("  • Implementation attacks possible")


def chinese_remainder_theorem(residues):
    """
    CRT: Reconstruct value from system of congruences
    residues = [(a_i, m_i), ...] where x ≡ a_i (mod m_i)
    """
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


def main():
    """Run all DH attack demonstrations"""
    
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "DIFFIE-HELLMAN VULNERABILITIES & ATTACKS" + " " * 12 + "║")
    print("╚" + "═" * 68 + "╝\n")
    
    # Demo 1: Pohlig-Hellman
    p_small = 1019  # 1018 = 2 × 509
    g_small = 2
    b_true = 123
    b_pub = pow(g_small, b_true, p_small)
    
    small_factors = [(2, 1), (509, 1)]
    pohlig_hellman_attack(p_small, g_small, b_pub, small_factors)
    
    # Demo 2: Small subgroup
    p = 23
    g = 11  # g^2 = 1 (mod 23)
    b = 7
    public = pow(g, b, p)
    small_subgroup_attack(p, g, public)
    
    # Demo 3: MITM Attack
    mitm_attack_unauth_dh()
    
    # Demo 4: Passive eavesdropping
    passive_eavesdropping_demo()
    
    # Demo 5: Replay attack
    replay_attack_demo()
    
    # Demo 6: Parameter validation
    parameter_validation_importance()
    
    print("\n" + "═" * 70)
    print("LESSONS FOR SECURE DH IMPLEMENTATION:")
    print("═" * 70)
    print("""
1. Parameter Generation:
   • Generate using RFC 3526 or RFC 7919 safe primes
   • Or use groups with large prime factor q dividing p-1
   
2. Input Validation:
   • Verify 1 < public_key < p-1
   • Verify public_key^q ≠ 1 mod p
   
3. Authentication:
   • Add signatures to prevent MITM
   • Use certificates or out-of-band verification
   
4. Ephemeral Keys:
   • Use DHE (Diffie-Hellman Ephemeral) not static DH
   • Generate new keypair per session
   
5. Hash the Shared Secret:
   • K = H(g^ab mod p || A || B)
   • Prevents small subgroup info leaks
   
Modern Standard (TLS 1.3):
  • Named groups with pre-approved parameters
  • 2048-bit or 3072-bit FFDH (Finite Field DH)
  • Or elliptic curve DH (ECDH) - preferred
""")
    print("═" * 70 + "\n")


if __name__ == "__main__":
    main()
