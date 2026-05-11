"""Caesar cipher attacks: brute force, frequency analysis, and IC analysis."""

from caesar import caesar_cipher, caesar_decipher, letter_to_index
from collections import Counter
import math

# French word frequency dictionary (minimal but functional)
FRENCH_COMMON_WORDS = {
    'le', 'de', 'un', 'et', 'a', 'que', 'la', 'en', 'est', 'pour',
    'il', 'qui', 'se', 'ne', 'par', 'pas', 'dans', 'ce', 'on', 'au',
    'elle', 'je', 'ou', 'tout', 'nous', 'vous', 'c', 'd', 'l', 'j',
    'du', 'avec', 'des', 'les', 'ces', 'son', 'sa', 'ses', 'son',
    'plus', 'peut', 'etre', 'bien', 'fait', 'fois', 'an', 'ans',
    'bonne', 'jour', 'jours', 'nuit', 'nuits', 'heure', 'heures',
    'monde', 'homme', 'femme', 'enfant', 'enfants', 'gens', 'ame',
    'coeur', 'corps', 'main', 'mains', 'pied', 'pieds', 'tete',
    'oeil', 'yeux', 'bouche', 'nez', 'oreille', 'oreilles',
    'maison', 'maisons', 'eau', 'terre', 'ciel', 'soleil', 'lune'
}

# French letter frequency (approximate)
FRENCH_FREQ = {
    'A': 0.0805, 'B': 0.0105, 'C': 0.0405, 'D': 0.0405, 'E': 0.1700,
    'F': 0.0095, 'G': 0.0095, 'H': 0.0085, 'I': 0.0705, 'J': 0.0055,
    'K': 0.0005, 'L': 0.0605, 'M': 0.0295, 'N': 0.0705, 'O': 0.0550,
    'P': 0.0265, 'Q': 0.0075, 'R': 0.0665, 'S': 0.0795, 'T': 0.0705,
    'U': 0.0605, 'V': 0.0135, 'W': 0.0035, 'X': 0.0045, 'Y': 0.0025,
    'Z': 0.0015
}


def calculate_index_of_coincidence(text):
    """
    Calculate index of coincidence (IC) for a given text.
    French IC ≈ 0.074, English ≈ 0.068, Random ≈ 0.038
    """
    # Remove non-alphabetic characters
    text = ''.join(c for c in text if c.isalpha()).upper()
    if len(text) < 2:
        return 0.0
    
    # Count letter frequencies
    freq = Counter(text)
    n = len(text)
    
    # IC = Σ(ni * (ni - 1)) / (N * (N - 1))
    ic = sum(count * (count - 1) for count in freq.values()) / (n * (n - 1))
    return ic


def calculate_chi_squared(text, expected_freq=FRENCH_FREQ):
    """
    Calculate chi-squared statistic to compare observed vs expected letter frequency.
    Lower score = better match to expected language.
    """
    text = ''.join(c for c in text if c.isalpha()).upper()
    if len(text) == 0:
        return float('inf')
    
    observed_freq = Counter(text)
    chi_sq = 0.0
    
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        expected = expected_freq[letter] * len(text)
        observed = observed_freq.get(letter, 0)
        if expected > 0:
            chi_sq += (observed - expected) ** 2 / expected
    
    return chi_sq


def brute_force_caesar(ciphertext, french_dict=FRENCH_COMMON_WORDS, top_n=5):
    """
    Brute force attack on Caesar cipher.
    Tests all 26 possible shifts and returns top candidates.
    
    Returns: list of (shift, plaintext, score) tuples
    """
    candidates = []
    
    for shift in range(26):
        plaintext = caesar_decipher(ciphertext, shift)
        
        # Score: count of recognized French words
        words = ''.join(c if c.isalpha() else ' ' for c in plaintext).lower().split()
        matched_words = sum(1 for word in words if word in french_dict)
        score = matched_words / len(words) if words else 0
        
        candidates.append((shift, plaintext, score))
    
    # Sort by score descending
    candidates.sort(key=lambda x: x[2], reverse=True)
    
    return candidates[:top_n]


def frequency_analysis_caesar(ciphertext):
    """
    Frequency analysis attack using Index of Coincidence.
    
    Returns: (most_likely_shift, plaintext, ic_value)
    """
    best_shift = 0
    best_ic = 0.0
    
    for shift in range(26):
        plaintext = caesar_decipher(ciphertext, shift)
        ic = calculate_index_of_coincidence(plaintext)
        
        if ic > best_ic:
            best_ic = ic
            best_shift = shift
    
    plaintext = caesar_decipher(ciphertext, best_shift)
    return best_shift, plaintext, best_ic


def chi_squared_attack_caesar(ciphertext, top_n=5):
    """
    Chi-squared frequency attack - compare letter distribution to French.
    Lower chi-squared = better match.
    
    Returns: list of (shift, plaintext, chi_squared) tuples
    """
    candidates = []
    
    for shift in range(26):
        plaintext = caesar_decipher(ciphertext, shift)
        chi_sq = calculate_chi_squared(plaintext)
        candidates.append((shift, plaintext, chi_sq))
    
    # Sort by chi-squared ascending (lower is better)
    candidates.sort(key=lambda x: x[2])
    
    return candidates[:top_n]


if __name__ == "__main__":
    print("=" * 70)
    print("CAESAR CIPHER ATTACKS")
    print("=" * 70)
    
    # Test message
    original = "thequickbrownfoxjumpsoverthelazydog"
    shift_key = 7
    ciphertext = caesar_cipher(original, shift_key)
    
    print(f"\nOriginal text:  {original}")
    print(f"Shift key:      {shift_key}")
    print(f"Ciphertext:     {ciphertext}")
    print(f"IC (original):  {calculate_index_of_coincidence(original):.4f}")
    print(f"IC (cipher):    {calculate_index_of_coincidence(ciphertext):.4f}")
    
    # Attack 1: Brute Force
    print("\n" + "-" * 70)
    print("ATTACK 1: BRUTE FORCE (Dictionary-based)")
    print("-" * 70)
    candidates = brute_force_caesar(ciphertext, top_n=3)
    for shift, plaintext, score in candidates:
        print(f"Shift {shift:2d}: {plaintext[:40]:40s} | Score: {score:.2%}")
    
    # Attack 2: IC Analysis
    print("\n" + "-" * 70)
    print("ATTACK 2: IC ANALYSIS (Index of Coincidence)")
    print("-" * 70)
    shift, plaintext, ic = frequency_analysis_caesar(ciphertext)
    print(f"Detected shift: {shift}")
    print(f"IC value:       {ic:.4f} (French avg: 0.0740)")
    print(f"Plaintext:      {plaintext[:60]}...")
    
    # Attack 3: Chi-squared
    print("\n" + "-" * 70)
    print("ATTACK 3: CHI-SQUARED FREQUENCY ANALYSIS")
    print("-" * 70)
    candidates = chi_squared_attack_caesar(ciphertext, top_n=3)
    for i, (shift, plaintext, chi_sq) in enumerate(candidates, 1):
        print(f"{i}. Shift {shift:2d}: χ² = {chi_sq:8.2f} | {plaintext[:40]}")
    
    # Real-world example with partial French text
    print("\n" + "=" * 70)
    print("REAL-WORLD EXAMPLE: French Caesar-encrypted message")
    print("=" * 70)
    french_msg = "bonjour comment ca va aujourd hui"
    cipher_msg = caesar_cipher(french_msg, 5)
    print(f"Original French:  {french_msg}")
    print(f"Encrypted (k=5):  {cipher_msg}")
    
    print("\nBrute force results (top 3):")
    candidates = brute_force_caesar(cipher_msg, top_n=3)
    for shift, plaintext, score in candidates:
        print(f"  Shift {shift:2d}: {plaintext:40s} | Match: {score:.1%}")
