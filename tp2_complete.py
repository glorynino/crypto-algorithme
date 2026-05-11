#!/usr/bin/env python3
"""
TP 2 - CRYPTOGRAPHIE SYMÉTRIQUE MODERNE
Complete test suite for RC4, DES/3DES, and AES with vulnerabilities
"""

import sys
import os

# Add paths for imports
crypto_root = '/home/matt-anis/Studies/Crypto'
sys.path.insert(0, crypto_root)
sys.path.insert(0, os.path.join(crypto_root, 'RC4'))
sys.path.insert(0, os.path.join(crypto_root, 'DES'))
sys.path.insert(0, os.path.join(crypto_root, 'AES'))


def print_section(title):
    """Print formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_subsection(title):
    """Print formatted subsection header"""
    print("\n" + "-" * 80)
    print(f"  {title}")
    print("-" * 80)


def exercise_2_1_rc4():
    """Exercise 2.1 - RC4 Stream Cipher"""
    print_section("EXERCICE 2.1 - RC4 (CHIFFREMENT PAR FLOT)")
    
    try:
        from rc4_attacks import (
            wep_vulnerability_demo,
            rc4_statistical_bias_analysis,
            rc4_keystream_correlation
        )
        
        print("\nRC4 is a stream cipher with significant vulnerabilities.")
        print("Despite being used in WEP/WPA, it has been thoroughly broken.\n")
        
        wep_vulnerability_demo()
        rc4_statistical_bias_analysis()
        rc4_keystream_correlation()
        
        print("\n✓ RC4 Exercises Completed")
        
    except Exception as e:
        print(f"✗ Error in RC4 exercise: {e}")


def exercise_2_2_des():
    """Exercise 2.2 - DES and Triple-DES"""
    print_section("EXERCICE 2.2 - DES ET TRIPLE-DES")
    
    try:
        from des_modes import (
            des_ecb_cbc_comparison,
            des_ecb_weakness_visualization,
            des_cbc_iv_sensitivity,
            triple_des_performance
        )
        
        print("\nDES: Data Encryption Standard (1977)")
        print("  • 56-bit key (now too small)")
        print("  • 64-bit blocks (vulnerable to birthday attacks)")
        print("  • Uses substitution-permutation network")
        print("  • Now deprecated, but 3DES still used for legacy systems\n")
        
        des_ecb_cbc_comparison()
        des_ecb_weakness_visualization()
        des_cbc_iv_sensitivity()
        triple_des_performance()
        
        print("\n✓ DES/3DES Exercises Completed")
        
    except Exception as e:
        print(f"✗ Error in DES exercise: {e}")


def exercise_2_3_aes():
    """Exercise 2.3 - AES Advanced Encryption Standard"""
    print_section("EXERCICE 2.3 - AES (ADVANCED ENCRYPTION STANDARD)")
    
    try:
        from aes_modes import (
            aes_modes_comparison,
            aes_key_size_comparison,
            aes_nonce_reuse_vulnerability,
            aes_cbc_avalanche_effect,
            aes_modes_chosen_ciphertext_attack
        )
        
        print("\nAES: Rijndael cipher (2001-present)")
        print("  • 128/192/256-bit keys")
        print("  • 128-bit blocks")
        print("  • Substitution-Permutation Network (SPN)")
        print("  • NIST standard, no known practical attacks\n")
        
        aes_modes_comparison()
        aes_key_size_comparison()
        aes_nonce_reuse_vulnerability()
        aes_cbc_avalanche_effect()
        aes_modes_chosen_ciphertext_attack()
        
        print("\n✓ AES Exercises Completed")
        
    except Exception as e:
        print(f"✗ Error in AES exercise: {e}")


def exercise_2_4_nist_finalists():
    """Exercise 2.4 - NIST AES Finalists"""
    print_section("EXERCICE 2.4 - LES 5 FINALISTES NIST (1997-2000)")
    
    try:
        from nist_finalists import (
            describe_finalists,
            comparison_table,
            security_analysis,
            benchmark_available_algorithms
        )
        
        print("\nNIST conducted a 3-year competition (1997-2000)")
        print("15 candidates → 5 finalists → Rijndael (AES) selected\n")
        
        describe_finalists()
        comparison_table()
        security_analysis()
        benchmark_available_algorithms()
        
        print("\n✓ NIST Finalists Analysis Completed")
        
    except Exception as e:
        print(f"✗ Error in NIST finalists exercise: {e}")


def comparison_summary():
    """Create comprehensive comparison table"""
    print_section("SYNTHÈSE: COMPARAISON RC4, DES, AES")
    
    print("""
┌─────────────┬──────────────┬──────────────┬──────────────┬──────────────┐
│  Critère    │      RC4     │      DES     │      AES     │   État       │
├─────────────┼──────────────┼──────────────┼──────────────┼──────────────┤
│ Clé (bits)  │  40-256      │      56      │  128-256     │              │
│ Bloc (bits) │   Stream     │      64      │     128      │              │
│ Tours       │   1 loop     │      16      │   10-14      │              │
│ Fondation   │    1987      │    1977      │   2001       │              │
├─────────────┼──────────────┼──────────────┼──────────────┼──────────────┤
│ Sécurité    │   ✗ Cassée   │   ✗ Cassée   │  ✓ Sûre      │              │
│ Vitesse     │  Rapide      │  Lent        │ Très rapide  │              │
│ Attaques    │   WEP, bias  │  Force brute │   Aucune     │              │
│ Usage       │   Obsolète   │   Legacy     │   Standard   │              │
└─────────────┴──────────────┴──────────────┴──────────────┴──────────────┘

Recommandations d'usage (2026):
  • RC4: ✗ JAMAIS utiliser (complètement cassé)
  • DES: ✗ Seulement pour compatibilité legacy
  • 3DES: ~ Accepté mais lent (migration recommandée)
  • AES: ✓ Standard obligatoire pour tout nouveau code

Modes conseillés pour AES:
  • Confidentiel seulement: AES-256-CTR
  • Intégrité + Confidentialité: AES-256-GCM ← RECOMMANDÉ
  • Pas d'authentification disponible: AES-256-CBC + HMAC
  
Algorithmes alternatif modernes:
  • ChaCha20-Poly1305: Équivalent sécurité, plus simple
  • AES-256-GCM: Plus sûr (authentification intégrée)
  • XChaCha20: Para environnements sans nonce 96-bit
    """)


def main():
    """Execute all TP 2 exercises"""
    
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 20 + "TP 2 - CRYPTOGRAPHIE SYMÉTRIQUE MODERNE" + " " * 18 + "║")
    print("║" + " " * 15 + "RC4, DES, 3DES, AES, et 5 finalistes NIST" + " " * 20 + "║")
    print("╚" + "═" * 78 + "╝")
    
    try:
        exercise_2_1_rc4()
    except Exception as e:
        print(f"\n✗ Erreur Exercice 2.1: {e}")
        import traceback
        traceback.print_exc()
    
    try:
        exercise_2_2_des()
    except Exception as e:
        print(f"\n✗ Erreur Exercice 2.2: {e}")
        import traceback
        traceback.print_exc()
    
    try:
        exercise_2_3_aes()
    except Exception as e:
        print(f"\n✗ Erreur Exercice 2.3: {e}")
        import traceback
        traceback.print_exc()
    
    try:
        exercise_2_4_nist_finalists()
    except Exception as e:
        print(f"\n✗ Erreur Exercice 2.4: {e}")
        import traceback
        traceback.print_exc()
    
    comparison_summary()
    
    print("\n" + "=" * 80)
    print("RÉSUMÉ: VULNÉRABILITÉS PAR ALGORITHME")
    print("=" * 80)
    print("""
RC4 (Stream Cipher):
  ✗ WEP Vulnerability: IV scheduling faible → clé trouvée avec ~1.5M packets
  ✗ Statistical bias: Biais dans 2ème byte et autres positions
  ✗ Key reuse: Même clé+IV → XOR revels M1⊕M2
  → Totalement cassé depuis 2001+ (JAMAIS utiliser)

DES (Block Cipher, 64 bits):
  ✗ Clé: 56 bits seulement (2^56 ≈ 7×10^16 clés)
  ✗ Bloc: 64 bits → collision birthday après ~2^32 blocs
  ✗ ECB faiblesse: Blocs identiques → chiffré identique
  ✗ Attaque brute force possible modernes
  → Obsolète (utiliser 3DES en transition, puis AES)

Triple-DES (3 × DES):
  ~ Clé: 112-168 bits (plus sûr que DES)
  ~ Lent: 3× plus lent que DES, 9× plus lent que AES
  ✓ Sûr en CBC/CTR mode avec random IV
  → Acceptable pour legacy, migration recommandée

AES (Block Cipher, 128 bits):
  ✓ Clé: 128/192/256 bits (sûr contre brute force)
  ✓ Bloc: 128 bits (grande marge avant collisions)
  ✓ Aucune attaque pratique known (2001-2026)
  ✗ ECB faiblesse: Même que DES, mais moins problé
  ✗ CTR nonce reuse: C1⊕C2 = M1⊕M2
  ✓ CBC-HMAC safe avec random IV
  ✓ AES-GCM: MEILLEUR (authentification incluse)
  → STANDARD REQUIS pour novo systems

NIST Finalists:
  • Rijndael → AES: Sélectionné (équilibre perf/sécurité)
  • Twofish: Sûr mais mémoire intensive (4KB S-boxes)
  • Serpent: Très sûr mais excessif (32 rounds = 5-10x lent)
  • RC6: Sûr mais complexe (rotations variables)
  • MARS: Sûr mais overcomplicated (32 rounds, SPN+Feistel hybride)
  
Raison du choix Rijndael:
  1. Rapidité: Meilleures performances
  2. Elegance: Mathématiquement simple et sûr
  3. Flexibilité: Tailles clé/bloc variables
  4. Hardware: Parfait pour implémentation AES-NI
  → Décision pragmatique correcte (25+ ans de succès)
    """)
    
    print("\n" + "=" * 80)
    print("FIN DU TP 2")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
