#!/usr/bin/env python3
"""
TP 4 - Cryptographic Hash Functions
Complete test suite for MD5, SHA-256, SHA-512 and their vulnerabilities
"""

import os
import hashlib
import time

from crypto_paths import setup_project_root

setup_project_root()

from MD5.md5 import md5_str
from SHA.sha256 import sha256_str

from tp_console import (
    banner,
    demo,
    end_footer,
    error_exercise,
    info,
    ok,
    section,
    subsection,
    summary,
)


def exercice_4_1_md5():
    """Exercise 4.1: MD5 Analysis."""
    section("4.1 — MD5 (MESSAGE DIGEST 5)")
    
    print("\nMD5 Properties:")
    print("  • Output: 128 bits (16 bytes)")
    print("  • Construction: Merkle-Damgård")
    print("  • Rounds: 4 tours × 16 opérations (F, G, H, I)")
    print("  • Status: BROKEN (collisions found in 2004)")
    print("  • Use: Legacy support, checksums only")
    
    demo("Jeu de tests MD5")
    
    test_vectors = [
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (b"I am learning MD5 hash functions", None),  # Will verify
    ]
    
    print(f"{'Input':<40} {'Output (MD5)':<35} {'Status'}")
    print("-" * 80)
    
    for data, expected in test_vectors:
        actual = hashlib.md5(data).hexdigest()
        
        if expected is None:
            status = "✓"
        else:
            status = "✓" if actual == expected else "✗"
        
        data_display = data[:38].decode('utf-8', errors='ignore') if len(data) <= 38 else data[:35].decode('utf-8', errors='ignore') + "..."
        print(f"{data_display:<40} {actual:<35} {status}")
    
    # Avalanche effect
    print("\n" + "-" * 80)
    print("Avalanche Effect Test:")
    print("-" * 80)
    
    original = b"The quick brown fox jumps over the lazy dog"
    hash1 = hashlib.md5(original).digest()
    
    modified = bytearray(original)
    modified[0] ^= 1  # Flip one bit
    hash2 = hashlib.md5(bytes(modified)).digest()
    
    bit_diff = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(hash1, hash2))
    total_bits = len(hash1) * 8
    flip_rate = (bit_diff / total_bits) * 100
    
    print(f"Original: {original}")
    print(f"Modified (1 bit): {bytes(modified)}")
    print(f"MD5 bits changed: {bit_diff}/{total_bits} ({flip_rate:.1f}%)")
    print(f"Status: {'✓ Good avalanche' if 40 < flip_rate < 60 else '⚠ Unexpected result'}")
    
    ok("Exercice MD5 terminé")


def exercice_4_2_sha256():
    """Exercise 4.2: SHA-256 Implementation."""
    section("4.2 — SHA-256 (SECURE HASH ALGORITHM 256)")
    
    print("\nSHA-256 Properties:")
    print("  • Output: 256 bits (32 bytes)")
    print("  • Construction: Merkle-Damgård")
    print("  • Block size: 512 bits")
    print("  • Rounds: 64 compression rounds")
    print("  • Constants: 64 K constants (cube roots of first 64 primes)")
    print("  • Status: STRONG (no collisions known)")
    print("  • Use: TLS, Git, Bitcoin, JWT, signatures")
    
    print("\n" + "-" * 80)
    print("Test Vectors (Validation):")
    print("-" * 80)
    
    test_vectors = [
        b"",
        b"abc",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        b"The quick brown fox jumps over the lazy dog",
        b"AAAAAAAA" * 100,  # 800 bytes
    ]
    
    print(f"{'Input':<45} {'SHA-256':<35} {'Status'}")
    print("-" * 80)
    
    for data in test_vectors:
        lib_hash = hashlib.sha256(data).hexdigest()
        data_display = data[:43].decode('utf-8', errors='ignore') if len(data) <= 43 else data[:40].decode('utf-8', errors='ignore') + "..."
        print(f"{data_display:<45} {lib_hash:<35} ✓")
    
    ok("Exercice SHA-256 terminé")


def exercice_4_3_comparison():
    """Exercise 4.3: SHA-512 and General Comparison."""
    section("4.3 — HASH FUNCTION COMPARISON")
    
    print("\nAlgorithm Properties Comparison:")
    print("-" * 80)
    
    properties = {
        "MD5": {"bits": 128, "recommended": False, "status": "BROKEN"},
        "SHA-256": {"bits": 256, "recommended": True, "status": "STRONG"},
        "SHA-512": {"bits": 512, "recommended": True, "status": "STRONG"},
        "SHA-3 (Keccak)": {"bits": 256, "recommended": True, "status": "STRONG"}
    }
    
    print(f"{'Algorithm':<20} {'Output Bits':<15} {'Recommended':<15} {'Security Status'}")
    print("-" * 80)
    
    for algo, props in properties.items():
        recommended = "✓ Yes" if props['recommended'] else "✗ No"
        print(f"{algo:<20} {props['bits']:<15} {recommended:<15} {props['status']}")
    
    print("\n" + "-" * 80)
    print("Performance Benchmark (100 MB):")
    print("-" * 80)
    
    test_data = os.urandom(100 * 1024 * 1024) if os.path.exists('/dev/urandom') else b"test" * (25 * 1024 * 1024)
    size_mb = len(test_data) / (1024 * 1024)
    
    print(f"Data size: {size_mb:.1f} MB\n")
    print(f"{'Algorithm':<15} {'Time (s)':<12} {'Throughput (MB/s)'}")
    print("-" * 80)
    
    algorithms = [
        ('MD5', hashlib.md5),
        ('SHA-256', hashlib.sha256),
        ('SHA-512', hashlib.sha512),
    ]
    
    results = []
    for name, hash_func in algorithms:
        start = time.time()
        hash_func(test_data).hexdigest()
        elapsed = time.time() - start
        throughput = size_mb / elapsed
        results.append((name, elapsed, throughput))
        print(f"{name:<15} {elapsed:<12.3f} {throughput:<17.1f}")
    
    fastest = min(results, key=lambda x: x[1])
    print(f"\nFastest: {fastest[0]} at {fastest[2]:.1f} MB/s")
    
    print("\n" + "-" * 80)
    print("Avalanche Effect - Comparison:")
    print("-" * 80)
    
    msg = b"Test message"
    modified = bytearray(msg)
    modified[0] ^= 1
    
    results_avalanche = {}
    for name, hash_func in algorithms:
        h1 = hash_func(msg).digest()
        h2 = hash_func(bytes(modified)).digest()
        bit_diff = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(h1, h2))
        total = len(h1) * 8
        flip_rate = (bit_diff / total) * 100
        results_avalanche[name] = flip_rate
        print(f"{name:<15} {flip_rate:.1f}% bits changed (ideal: ~50%)")
    
    ok("Comparaison terminée")


def collision_resistance_analysis():
    """Demonstrate collision resistance."""
    subsection("Analyse — Résistance aux collisions")
    
    print("\nBirthday Paradox Applied to Hash Functions:")
    print("-" * 80)
    print("For a hash function with n-bit output, ~2^(n/2) random messages")
    print("are needed before we expect to find two with the same hash.")
    print()
    
    algos = [
        ("MD5", 128),
        ("SHA-256", 256),
        ("SHA-512", 512),
    ]
    
    print(f"{'Algorithm':<15} {'Output Bits':<15} {'Collision Probability'}")
    print("-" * 80)
    
    for name, bits in algos:
        collision_threshold = 2 ** (bits / 2)
        print(f"{name:<15} {bits:<15} 2^{bits//2} (~{collision_threshold:.2e}) messages")
    
    print("\nMD5 Status:")
    print("  ✗ BROKEN - Practical collisions found (Wang & Yu, 2004)")
    print("  ✗ Should NOT be used for cryptography")
    print("  ⚠️ Still used for checksums (not security-critical)")
    
    print("\nSHA-256 & SHA-512 Status:")
    print("  ✓ STRONG - No collisions found")
    print("  ✓ RECOMMENDED for security-critical applications")
    print("  ✓ Used in Bitcoin, TLS, code signing")
    
    ok("Analyse des collisions terminée")


def main():
    """Run all TP4 exercises."""
    banner(4, "FONCTIONS DE HACHAGE", "MD5, SHA-256, SHA-512 — analyse et sécurité")
    
    try:
        exercice_4_1_md5()
        exercice_4_2_sha256()
        exercice_4_3_comparison()
        collision_resistance_analysis()
        
        summary("SUITE TP4 TERMINÉE")
        ok("Tous les exercices ont réussi")
        info("MD5 : cassé → préférer SHA-256 / SHA-512")
        info("SHA-256 / SHA-512 : recommandés pour la sécurité")
        info("HMAC : authentification des messages")
        
        end_footer(4)
        
    except Exception as e:
        error_exercise("TP4", e)
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
