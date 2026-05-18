#!/usr/bin/env python3
"""
TP 3 - CRYPTOGRAPHIE ASYMÉTRIQUE
Complete test suite for DH, RSA, ElGamal, and ECC with vulnerabilities
"""

from crypto_paths import setup_tp3_paths

setup_tp3_paths()

from tp_console import (
    banner,
    end_footer,
    error_exercise,
    print_block,
    section,
    summary,
)


def exercise_3_1_dh():
    """Exercise 3.1 - Diffie-Hellman"""
    section("3.1 — DIFFIE-HELLMAN (ÉCHANGE DE CLÉS)")
    
    try:
        from dh import DH, DH_Parameters, test_basic_dh
        from dh_attacks import (
            pohlig_hellman_attack,
            small_subgroup_attack,
            mitm_attack_unauth_dh,
            passive_eavesdropping_demo,
            replay_attack_demo,
            parameter_validation_importance
        )
        
        print("\nDiffie-Hellman Key Exchange:")
        print("  • 1976: Whitfield Diffie & Martin Hellman")
        print("  • Allows secure key establishment over public channel")
        print("  • Based on discrete logarithm problem (hard in Fp*)")
        print("  • NOT authenticated (vulnerable to MITM)\n")
        
        test_basic_dh()
        print("\n")
        pohlig_hellman_attack(1019, 2, pow(2, 123, 1019), [(2, 1), (509, 1)])
        
        print("\n✓ DH Exercises Completed")
        
    except Exception as e:
        print(f"✗ Error in DH exercise: {e}")
        import traceback
        traceback.print_exc()


def exercise_3_2_rsa():
    """Exercise 3.2 - RSA"""
    section("3.2 — RSA (CHIFFREMENT ASYMÉTRIQUE)")
    
    try:
        from rsa import generate_keypair, test_rsa
        from rsa_attacks import (
            small_exponent_attack,
            common_modulus_attack,
            textbook_rsa_homomorphic_property
        )
        
        print("\nRSA (Rivest-Shamir-Adleman):")
        print("  • 1977: First practical public-key cryptosystem")
        print("  • Based on difficulty of integer factorization")
        print("  • Used for both encryption and digital signatures")
        print("  • Requires careful padding (OAEP, PSS)\n")
        
        test_rsa()
        
        # Demo attacks
        print("\nDemonstrating RSA Vulnerabilities:")
        n_small = 3233
        e_small = 3
        m_small = 42
        c_small = pow(m_small, e_small, n_small)
        small_exponent_attack(n_small, e_small, c_small)
        
        print("\n✓ RSA Exercises Completed")
        
    except Exception as e:
        print(f"✗ Error in RSA exercise: {e}")
        import traceback
        traceback.print_exc()


def exercise_3_3_elgamal():
    """Exercise 3.3 - ElGamal"""
    section("3.3 — ELGAMAL (CHIFFREMENT À CLÉS PUBLIQUES)")
    
    try:
        from elgamal import test_elgamal
        from elgamal_attacks import (
            elgamal_homomorphic_attack,
            small_subgroup_attack_elgamal,
            distinguishing_attack_semantics
        )
        
        print("\nElGamal Encryption:")
        print("  • 1984: Taher ElGamal")
        print("  • Based on Diffie-Hellman key exchange")
        print("  • Probabilistic encryption (randomness per message)")
        print("  • Homomorphic properties (can be abused)\n")
        
        test_elgamal()
        
        # Attack demonstrations
        print("\nDemonstrating ElGamal Vulnerabilities:")
        elgamal_homomorphic_attack()
        
        print("\n✓ ElGamal Exercises Completed")
        
    except Exception as e:
        print(f"✗ Error in ElGamal exercise: {e}")
        import traceback
        traceback.print_exc()


def exercise_3_4_ecc():
    """Exercise 3.4 - Elliptic Curve Cryptography"""
    section("3.4 — CRYPTOGRAPHIE SUR COURBES ELLIPTIQUES")
    
    try:
        from ecc import ecdh_example, ecdsa_signature_example
        from ecc_attacks import (
            small_subgroup_attack_ecc,
            timing_attack_ecc,
            ecdsa_nonce_reuse
        )
        
        print("\nElliptic Curve Cryptography:")
        print("  • 1985: Neal Koblitz & Victor Miller (independently)")
        print("  • Based on elliptic curve discrete logarithm problem")
        print("  • Smaller keys than RSA/DH for same security")
        print("  • Modern standard (TLS 1.3, Signal, Bitcoin)\n")
        
        ecdh_example()
        ecdsa_signature_example()
        
        # Attack demonstrations
        print("\nDemonstrating ECC Vulnerabilities:")
        timing_attack_ecc()
        ecdsa_nonce_reuse()
        
        print("\n✓ ECC Exercises Completed")
        
    except Exception as e:
        print(f"✗ Error in ECC exercise: {e}")
        import traceback
        traceback.print_exc()


def comparison_summary():
    """Create comprehensive comparison table"""
    summary("COMPARAISON DH, RSA, ELGAMAL, ECC")
    
    print_block("""
┌─────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
│  Critère    │      DH      │      RSA     │   ElGamal    │      ECC     │
├─────────────┼──────────────┼──────────────┼──────────────┼──────────────┤
│ Année       │     1976     │     1977     │     1984     │   1985(+)    │
│ Fondation   │  Disc. Log   │  PQC Hard    │  Disc. Log   │   ECDLP      │
│ Clé Taille  │  2048+ bits  │  2048+ bits  │  2048+ bits  │  256-384 bits│
│ Signature   │      ✗       │      ✓       │      ✓       │      ✓       │
│ Vitesse     │      ◐       │      ◐       │      ◐       │      ✓ Rapide│
│ Signa. Taille│     ✗        │    256-512B  │    512B+     │    64B (256) │
├─────────────┼──────────────┼──────────────┼──────────────┼──────────────┤
│ Sécurité    │   ✓ Sûr      │   ✓ Sûr      │  ◐ Si padding│  ✓ Sûr       │
│ Attacks     │  Small subgp │  All textbook│  Homomorphic │  Timing, etc │
│ Usage       │  Key exchange│  Encryption  │    Legacy     │  Moderne     │
│ Productio.  │      ◐       │      ✓       │      ✗       │      ✓       │
└─────────────┴──────────────┴──────────────┴──────────────┴──────────────┘

Recommandations d'usage (2026):

  KEY EXCHANGE (Perfect Forward Secrecy):
    ✓ ECDH: X25519 / X448 (RECOMMANDÉ)
    ~ DHE: RFC 7919 safe primes (compatible)
    ✗ Static DH (weak)
    ✗ No encryption: RSA (use for signatures)
    
  ENCRYPTION:
    ✓ Hybrid: ECDH + AES-256-GCM
    ✓ Or: RSA-OAEP + AES-256-GCM (legacy)
    ✗ Textbook RSA/ElGamal without padding
    ✗ Deterministic encryption
    
  SIGNATURES:
    ✓ EdDSA (Ed25519) - moderne, simple, sûr
    ✓ ECDSA (P-256) - standard
    ~ RSA-PSS (acceptable)
    ✗ ECDSA with weak k
    ✗ Textbook RSA signature
    
  AUTHENTICATION:
    ✓ Digital certificates (X.509)
    ✓ Public key infrastructure (PKI)
    ✓ Or: Out-of-band verification (Signal)
    
Algorithme sélection moderne (TLS 1.3):
  • Handshake: ECDHE (X25519)
  • Signature: ECDSA-P256 ou EdDSA
  • Authentication: X.509 certificates
  • Parfait Forward Secrecy: ✓ Automatique
    """)


def main():
    """Execute all TP 3 exercises"""
    banner(3, "CRYPTOGRAPHIE ASYMÉTRIQUE", "Diffie-Hellman, RSA, ElGamal, courbes elliptiques")
    
    try:
        exercise_3_1_dh()
    except Exception as e:
        error_exercise("3.1", e)
    
    try:
        exercise_3_2_rsa()
    except Exception as e:
        error_exercise("3.2", e)
    
    try:
        exercise_3_3_elgamal()
    except Exception as e:
        error_exercise("3.3", e)
    
    try:
        exercise_3_4_ecc()
    except Exception as e:
        error_exercise("3.4", e)
    
    comparison_summary()
    
    end_footer(3)


if __name__ == "__main__":
    main()
