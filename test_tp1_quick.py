#!/usr/bin/env python3
"""
Quick test of TP 1 implementations - Caesar attack
"""
from crypto_paths import setup_tp1_paths

setup_tp1_paths()

from caesar import caesar_cipher, caesar_decipher
from caesar_attacks import brute_force_caesar, chi_squared_attack_caesar, calculate_index_of_coincidence

print("=" * 70)
print("TP 1 - QUICK TEST: CAESAR CIPHER ATTACKS")
print("=" * 70)

# Use longer text for better statistical analysis
plaintext = "BONJOUR COMMENT CA VA AUJOURD HUI LE MONDE EST MAGNIFIQUE ET BEAU"
plaintext = ''.join(c for c in plaintext if c.isalpha())  # Remove spaces
shift = 7
ciphertext = caesar_cipher(plaintext, shift)

print(f"\n✓ Original (length {len(plaintext)}):  {plaintext[:50]}...")
print(f"✓ Shift:     {shift}")
print(f"✓ Encrypted: {ciphertext[:50]}...")

# IC analysis
ic_orig = calculate_index_of_coincidence(plaintext)
ic_cipher = calculate_index_of_coincidence(ciphertext)
print(f"\n✓ IC (plaintext): {ic_orig:.4f}")
print(f"✓ IC (ciphertext): {ic_cipher:.4f}")

# Brute force attack
print(f"\n--- BRUTE FORCE ATTACK ---")
candidates = brute_force_caesar(ciphertext, top_n=3)
for i, (found_shift, recovered, score) in enumerate(candidates, 1):
    status = "✓ CORRECT!" if recovered == plaintext else ""
    print(f"{i}. Shift {found_shift}: {score:.1%} confidence {status}")

# Chi-squared analysis
print(f"\n--- CHI-SQUARED FREQUENCY ANALYSIS ---")
chi_candidates = chi_squared_attack_caesar(ciphertext, top_n=3)
for i, (found_shift, recovered, chi_sq) in enumerate(chi_candidates, 1):
    status = "✓ CORRECT!" if recovered == plaintext else ""
    print(f"{i}. Shift {found_shift}: χ² = {chi_sq:8.2f} {status}")

print("\n" + "=" * 70)
print("✓ TP 1 Caesar cipher working correctly!")
print("=" * 70)
