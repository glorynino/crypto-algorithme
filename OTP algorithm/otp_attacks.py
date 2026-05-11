"""One-Time Pad (OTP/Vernam) attack: key reuse vulnerability and crib dragging."""

import os
from collections import Counter
from otp import encryption, decryption


def xor_bytes(a, b):
    """XOR two byte sequences."""
    return bytes(x ^ y for x, y in zip(a, b))


def otp_key_reuse_attack(message1, message2):
    """
    Demonstrate OTP key reuse vulnerability.
    
    If two messages are encrypted with the same key:
    C1 = M1 ⊕ K
    C2 = M2 ⊕ K
    
    Then C1 ⊕ C2 = M1 ⊕ M2 (the key cancels out!)
    
    The attacker gets: C1 ⊕ C2 = M1 ⊕ M2
    which leaks information about both plaintext messages.
    """
    # Encrypt both messages with the same key (vulnerability!)
    m1_bytes = message1.encode() if isinstance(message1, str) else message1
    m2_bytes = message2.encode() if isinstance(message2, str) else message2
    
    # Use same key for both (this is the attack setup)
    key = os.urandom(max(len(m1_bytes), len(m2_bytes)))
    
    c1 = bytes(m ^ k for m, k in zip(m1_bytes, key))
    c2 = bytes(m ^ k for m, k in zip(m2_bytes, key))
    
    # XOR the ciphertexts
    xor_result = xor_bytes(c1, c2)
    
    return {
        'message1': message1,
        'message2': message2,
        'key': key,
        'ciphertext1': c1,
        'ciphertext2': c2,
        'ciphertext1_xor_ciphertext2': xor_result,
        'message1_xor_message2': xor_bytes(m1_bytes, m2_bytes)
    }


def demonstrate_xor_properties(text1, text2):
    """Show information leaked by XOR of two messages."""
    t1 = text1.encode()
    t2 = text2.encode()
    xor_text = xor_bytes(t1, t2)
    
    print(f"Text 1:              {text1}")
    print(f"Text 2:              {text2}")
    print(f"Length 1:            {len(t1)}")
    print(f"Length 2:            {len(t2)}")
    print(f"M1 ⊕ M2:            {xor_text}")
    print(f"M1 ⊕ M2 (hex):      {xor_text.hex()}")
    
    # Statistical analysis
    xor_entropy = calculate_entropy(xor_text)
    print(f"Entropy (M1⊕M2):    {xor_entropy:.2f} bits")
    
    return xor_text


def calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    
    freq = Counter(data)
    n = len(data)
    entropy = 0.0
    
    for count in freq.values():
        p = count / n
        entropy -= p * (math.log2(p) if p > 0 else 0)
    
    return entropy


def crib_dragging_attack(ciphertext1, ciphertext2, known_plaintext_crib):
    """
    Crib dragging attack: if we suspect a portion of plaintext,
    we can test it against the XOR result M1 ⊕ M2.
    
    C1 ⊕ C2 = M1 ⊕ M2
    If we guess part of M1 = "crib", we can compute what M2 must be at that position.
    """
    xor_c = xor_bytes(ciphertext1, ciphertext2)
    crib_bytes = known_plaintext_crib.encode()
    
    results = []
    
    # Slide the crib across the XOR result
    for position in range(len(xor_c) - len(crib_bytes) + 1):
        xor_segment = xor_c[position:position + len(crib_bytes)]
        
        # If crib is at this position in M1, then M2 at this position is:
        implied_m2 = xor_bytes(crib_bytes, xor_segment)
        
        # Check if result is printable ASCII (heuristic for valid text)
        if all(32 <= b < 127 for b in implied_m2):
            results.append({
                'position': position,
                'crib': known_plaintext_crib,
                'implied_message2_segment': implied_m2.decode('ascii', errors='replace'),
                'confidence': 'HIGH' if all(b not in [0, 255] for b in implied_m2) else 'MEDIUM'
            })
    
    return results


def frequency_analysis_on_xor(xor_result, language_freq=None):
    """
    Analyze frequency patterns in M1 ⊕ M2 to extract information.
    
    The XOR of two texts still preserves some statistical properties
    that can be exploited.
    """
    if language_freq is None:
        # English letter frequency
        language_freq = {
            'E': 0.1185, 'T': 0.0910, 'A': 0.0812, 'O': 0.0770,
            'I': 0.0695, 'N': 0.0672, 'S': 0.0628, 'H': 0.0609,
            'R': 0.0602, 'D': 0.0432, 'L': 0.0398, 'C': 0.0278,
            'U': 0.0276, 'M': 0.0241, 'W': 0.0236, 'F': 0.0223,
            'G': 0.0202, 'Y': 0.0197, 'P': 0.0193, 'B': 0.0149,
            'V': 0.0098, 'K': 0.0077, 'J': 0.0015, 'X': 0.0015,
            'Q': 0.0010, 'Z': 0.0007
        }
    
    freq = Counter(xor_result)
    n = len(xor_result)
    
    # Analyze byte distribution
    entropy = calculate_entropy(xor_result)
    
    return {
        'entropy': entropy,
        'byte_distribution': dict(freq),
        'total_bytes': n,
        'unique_bytes': len(freq)
    }


import math


if __name__ == "__main__":
    print("=" * 70)
    print("ONE-TIME PAD (OTP) ATTACKS")
    print("=" * 70)
    
    # ATTACK 1: Key Reuse Vulnerability
    print("\n" + "-" * 70)
    print("ATTACK 1: KEY REUSE VULNERABILITY")
    print("-" * 70)
    
    m1 = "THEQUICKBROWNFOX"
    m2 = "THELAZYHUMANITY"
    
    result = otp_key_reuse_attack(m1, m2)
    
    print(f"\nScenario: Attacker intercepts two OTP-encrypted messages")
    print(f"          that were encrypted with THE SAME KEY (VULNERABLE!)\n")
    print(f"Message 1:                {result['message1']}")
    print(f"Message 2:                {result['message2']}")
    print(f"Ciphertext 1 (hex):       {result['ciphertext1'].hex()[:40]}...")
    print(f"Ciphertext 2 (hex):       {result['ciphertext2'].hex()[:40]}...")
    
    print(f"\n--- ATTACK: XOR the two ciphertexts ---")
    print(f"C1 ⊕ C2 = M1 ⊕ M2 (key cancels out!)\n")
    
    xor_result = result['ciphertext1_xor_ciphertext2']
    print(f"C1 ⊕ C2 (bytes):         {list(xor_result[:16])}")
    print(f"M1 ⊕ M2 (bytes):         {list(result['message1_xor_message2'][:16])}")
    print(f"Match: {'✓ YES' if xor_result == result['message1_xor_message2'] else '✗ NO'}")
    
    # ATTACK 2: XOR Analysis
    print("\n" + "-" * 70)
    print("ATTACK 2: INFORMATION LEAKAGE via XOR")
    print("-" * 70)
    
    print("\nXOR leaks structural information about both messages:")
    text1 = "HELLO WORLD"
    text2 = "GOODBYE MOON"
    
    demonstrate_xor_properties(text1, text2)
    
    # ATTACK 3: Crib Dragging
    print("\n" + "-" * 70)
    print("ATTACK 3: CRIB DRAGGING")
    print("-" * 70)
    
    m1_crib = "THE"
    m2_crib = "SECRET"
    
    c1, key = encryption(m1_crib)
    c2, _ = encryption(m2_crib)  # SAME KEY (reused) - vulnerability!
    
    # Attacker only knows ciphertexts and suspects m1 contains "THE"
    print(f"\nAttacker knows:")
    print(f"  C1 = {c1.hex()}")
    print(f"  C2 = {c2.hex()}")
    print(f"  Suspects M1 contains 'THE'")
    
    print(f"\nAttacker tries 'THE' at different positions in M1...")
    
    # For short example
    c1_long, key_shared = encryption("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")
    c2_long, _ = encryption("THEATTACKERHASTHEKEY", )  # Reuse same key
    
    crib_results = crib_dragging_attack(c1_long, c2_long, "THE")
    
    print(f"\nPositions where 'THE' likely appears in M1:")
    for i, result in enumerate(crib_results[:5], 1):
        print(f"  Position {result['position']:2d}: "
              f"M2 would have '{result['implied_message2_segment'].strip()}' "
              f"[{result['confidence']}]")
    
    # Frequency Analysis
    print("\n" + "-" * 70)
    print("ATTACK 4: FREQUENCY ANALYSIS")
    print("-" * 70)
    
    xor_long = xor_bytes(c1_long, c2_long)
    freq_info = frequency_analysis_on_xor(xor_long)
    
    print(f"\nStatistics on C1 ⊕ C2:")
    print(f"  Total bytes:    {freq_info['total_bytes']}")
    print(f"  Unique values:  {freq_info['unique_bytes']}")
    print(f"  Entropy:        {freq_info['entropy']:.2f} bits")
    print(f"  (Random would be ~{math.log2(256):.2f} bits)")
    
    # SECURITY IMPLICATIONS
    print("\n" + "=" * 70)
    print("SECURITY IMPLICATIONS")
    print("=" * 70)
    print("""
OTP THEORETICAL SECURITY:
  ✓ Perfectly secret IF:
    - Key is truly random
    - Key is kept secret
    - Key length ≥ message length
    - Key is NEVER REUSED

OTP PRACTICAL VULNERABILITIES:
  ✗ Key management: Distributing and storing long random keys
  ✗ Key reuse: Single key compromise leaks all messages
  ✗ Ciphertext-only attacks: If key is reused, C1⊕C2 = M1⊕M2
  ✗ Crib dragging: Known plaintext fragments reveal other messages
  ✗ Authentication: OTP provides no authentication/integrity checking

REAL-WORLD EXAMPLE - Venona Project:
  The Soviet Union reused OTP keys during WWII.
  This allowed cryptanalysts to recover classified messages
  decades later through known-plaintext attacks.

MODERN ALTERNATIVES:
  - Stream ciphers (ChaCha20, Salsa20): random-looking but deterministic
  - Block ciphers (AES-CTR, AES-GCM): authenticated encryption
  - Key derivation (HKDF, Argon2): safe key generation
    """)
