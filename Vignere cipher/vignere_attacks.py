"""Vigenère cipher attacks: Kasiski test, IC analysis, and key recovery."""

from vignere import encrypt_vignere, decrypt_vignere, letter_to_index
from collections import Counter
import math
from math import gcd
from functools import reduce

# French letter frequency
FRENCH_FREQ = {
    'A': 0.0805, 'B': 0.0105, 'C': 0.0405, 'D': 0.0405, 'E': 0.1700,
    'F': 0.0095, 'G': 0.0095, 'H': 0.0085, 'I': 0.0705, 'J': 0.0055,
    'K': 0.0005, 'L': 0.0605, 'M': 0.0295, 'N': 0.0705, 'O': 0.0550,
    'P': 0.0265, 'Q': 0.0075, 'R': 0.0665, 'S': 0.0795, 'T': 0.0705,
    'U': 0.0605, 'V': 0.0135, 'W': 0.0035, 'X': 0.0045, 'Y': 0.0025,
    'Z': 0.0015
}

FRENCH_IC_AVG = 0.074


def calculate_index_of_coincidence(text):
    """Calculate IC for a given text."""
    text = ''.join(c for c in text if c.isalpha()).upper()
    if len(text) < 2:
        return 0.0
    
    freq = Counter(text)
    n = len(text)
    ic = sum(count * (count - 1) for count in freq.values()) / (n * (n - 1))
    return ic


def kasiski_test(ciphertext, trigram_min_length=3):
    """
    Kasiski examination: find repeated trigrams (or longer patterns)
    to estimate the likely key length.
    
    Returns: list of (pattern, positions, distances, estimated_key_lengths)
    """
    # Remove spaces and normalize
    text = ''.join(c for c in ciphertext if c.isalpha()).upper()
    
    repeated_patterns = {}
    
    # Find trigrams and their positions
    for length in [3, 4, 5]:
        for i in range(len(text) - length + 1):
            pattern = text[i:i+length]
            
            if pattern not in repeated_patterns:
                repeated_patterns[pattern] = []
            repeated_patterns[pattern].append(i)
    
    # Filter patterns that repeat
    results = []
    for pattern, positions in repeated_patterns.items():
        if len(positions) > 1:  # Only patterns that repeat
            distances = []
            for i in range(len(positions) - 1):
                distances.append(positions[i+1] - positions[i])
            
            # Find all divisors of distances (possible key lengths)
            all_divisors = set()
            for distance in distances:
                # Get divisors of each distance
                for d in range(1, distance + 1):
                    if distance % d == 0:
                        all_divisors.add(d)
            
            results.append((pattern, positions.copy(), distances, sorted(all_divisors)))
    
    # Sort by most frequent patterns first
    results.sort(key=lambda x: len(x[1]), reverse=True)
    
    return results


def estimate_key_length_kasiski(ciphertext, top_n=5):
    """
    Estimate key length using Kasiski examination.
    
    Returns: list of (key_length, frequency) sorted by likelihood
    """
    results = kasiski_test(ciphertext)
    
    key_length_votes = Counter()
    
    for pattern, positions, distances, divisors in results:
        # Vote for each divisor
        for divisor in divisors:
            if divisor > 0:
                key_length_votes[divisor] += 1
    
    # Sort by vote count
    sorted_votes = sorted(key_length_votes.items(), key=lambda x: x[1], reverse=True)
    
    return sorted_votes[:top_n]


def index_of_coincidence_attack(ciphertext):
    """
    Use IC for each possible key length to find the actual length.
    The correct key length should give average IC close to 0.074 (French).
    """
    text = ''.join(c for c in ciphertext if c.isalpha()).upper()
    
    ic_scores = {}
    
    for key_length in range(1, min(len(text) // 10, 20)):
        # Split ciphertext into key_length subsequences
        subsequences = ['' for _ in range(key_length)]
        for i, char in enumerate(text):
            subsequences[i % key_length] += char
        
        # Calculate average IC of all subsequences
        avg_ic = sum(calculate_index_of_coincidence(sub) for sub in subsequences) / key_length
        ic_scores[key_length] = avg_ic
    
    # The correct key length should have IC closest to FRENCH_IC_AVG
    best_length = min(ic_scores.items(), 
                     key=lambda x: abs(x[1] - FRENCH_IC_AVG))
    
    return ic_scores, best_length


def recover_key_from_ic(ciphertext, key_length):
    """
    Once key length is known, recover the key using IC and frequency analysis.
    Each position in the key is a Caesar shift, which we can find via frequency.
    """
    text = ''.join(c for c in ciphertext if c.isalpha()).upper()
    
    # Split into subsequences
    subsequences = ['' for _ in range(key_length)]
    for i, char in enumerate(text):
        subsequences[i % key_length] += char
    
    key = []
    
    # For each subsequence, find the shift that best matches French frequency
    for sub in subsequences:
        best_shift = 0
        best_chi_sq = float('inf')
        
        for shift in range(26):
            # Decrypt this subsequence with this shift
            decrypted = ''.join(
                chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
                for c in sub
            )
            
            # Calculate chi-squared against French frequency
            freq = Counter(decrypted)
            chi_sq = 0.0
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                expected = FRENCH_FREQ[letter] * len(decrypted)
                observed = freq.get(letter, 0)
                if expected > 0:
                    chi_sq += (observed - expected) ** 2 / expected
            
            if chi_sq < best_chi_sq:
                best_chi_sq = chi_sq
                best_shift = shift
        
        # Convert shift to letter
        key.append(chr(best_shift + ord('A')))
    
    return ''.join(key)


def find_gcd_of_distances(ciphertext):
    """
    Find GCD of all trigram distances - often gives key length.
    """
    results = kasiski_test(ciphertext)
    all_distances = []
    
    for pattern, positions, distances, divisors in results:
        all_distances.extend(distances)
    
    if not all_distances:
        return None
    
    gcd_value = reduce(gcd, all_distances)
    return gcd_value


if __name__ == "__main__":
    print("=" * 70)
    print("VIGENÈRE CIPHER ATTACKS")
    print("=" * 70)
    
    # Test message (repeat it to make trigrams visible)
    original = "thequickbrownfoxjumpsoverthelazydog" * 3
    key = "SECRET"
    ciphertext = encrypt_vignere(original, key)
    
    print(f"\nOriginal text: {original[:50]}...")
    print(f"Key:          {key}")
    print(f"Ciphertext:   {ciphertext[:50]}...")
    
    # Attack 1: Kasiski Examination
    print("\n" + "-" * 70)
    print("ATTACK 1: KASISKI EXAMINATION (Trigram Analysis)")
    print("-" * 70)
    
    print("\nRepeated trigrams found:")
    kasiski_results = kasiski_test(ciphertext)
    for pattern, positions, distances, divisors in kasiski_results[:5]:
        print(f"  Pattern '{pattern}': positions {positions[:3]}, "
              f"distances {distances}, possible key lengths: {divisors[:8]}")
    
    # Estimate key length
    key_length_estimates = estimate_key_length_kasiski(ciphertext, top_n=5)
    print(f"\nEstimated key lengths (by Kasiski):")
    for key_len, votes in key_length_estimates:
        print(f"  Length {key_len}: {votes} votes")
    
    # GCD method
    gcd_value = find_gcd_of_distances(ciphertext)
    print(f"\nGCD of all trigram distances: {gcd_value}")
    
    # Attack 2: IC Analysis
    print("\n" + "-" * 70)
    print("ATTACK 2: INDEX OF COINCIDENCE ANALYSIS")
    print("-" * 70)
    
    ic_scores, (best_length, best_ic) = index_of_coincidence_attack(ciphertext)
    
    print(f"\nIC Analysis Results (showing IC for each key length):")
    print(f"{'Length':<8} {'IC Value':<12} {'Delta from French':<20}")
    print("-" * 40)
    for length in sorted(ic_scores.keys())[:15]:
        ic = ic_scores[length]
        delta = abs(ic - FRENCH_IC_AVG)
        print(f"{length:<8} {ic:<12.4f} {delta:<20.4f}")
    
    print(f"\nBest estimated key length: {best_length} (IC: {best_ic:.4f})")
    print(f"French average IC: 0.0740")
    
    # Attack 3: Key Recovery
    print("\n" + "-" * 70)
    print("ATTACK 3: KEY RECOVERY (using frequency analysis)")
    print("-" * 70)
    
    estimated_key = recover_key_from_ic(ciphertext, best_length)
    print(f"\nOriginal key:     {key}")
    print(f"Recovered key:    {estimated_key}")
    
    if len(estimated_key) == len(key):
        matches = sum(1 for a, b in zip(estimated_key, key) if a == b)
        print(f"Correct positions: {matches}/{len(key)}")
    
    # Decrypt with recovered key
    decrypted = decrypt_vignere(ciphertext, estimated_key)
    print(f"\nDecrypted text: {decrypted[:60]}...")
    print(f"Original text:  {original[:60]}...")
    
    # Real-world example
    print("\n" + "=" * 70)
    print("REAL-WORLD EXAMPLE: Longer French text")
    print("=" * 70)
    
    french_text = ("bonjour comment ca va aujourd hui le monde est magnifique " * 5).upper()
    key_real = "CRYPTO"
    cipher_real = encrypt_vignere(french_text, key_real)
    
    print(f"\nOriginal (length {len(french_text)}): {french_text[:60]}...")
    print(f"Key: {key_real}")
    print(f"Ciphertext: {cipher_real[:60]}...")
    
    ic_scores2, (best_len2, best_ic2) = index_of_coincidence_attack(cipher_real)
    print(f"\nEstimated key length from IC: {best_len2}")
    
    recovered_key2 = recover_key_from_ic(cipher_real, best_len2)
    print(f"Original key:  {key_real}")
    print(f"Recovered key: {recovered_key2}")
