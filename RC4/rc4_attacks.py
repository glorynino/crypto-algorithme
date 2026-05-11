"""
RC4 Vulnerabilities and Attacks: WEP weakness, IV correlation, statistical bias
"""

try:
    from rc4 import _ksa, _prga, _coerce_bytes
except ImportError:
    from .rc4 import _ksa, _prga, _coerce_bytes

from collections import Counter
import os


def wep_vulnerability_demo():
    """
    WEP (Wired Equivalent Privacy) Vulnerability
    
    In WEP, the IV is prepended to the root key:
    effective_key = IV (3 bytes) + root_key (5 bytes)
    
    Problem: Many IV values lead to weak KSA states where the first keystream byte
    is correlated with key bytes. With ~1.5 million packets, attackers can recover the key.
    """
    print("\n" + "=" * 70)
    print("WEP VULNERABILITY: Weak IV + Key Scheduling Algorithm")
    print("=" * 70)
    
    root_key = b"WEP_ROOT_KEY"
    
    print(f"\nScenario: WEP router with root key: {root_key}")
    print(f"Attacker intercepts packets with sequential IVs...\n")
    
    keystream_samples = []
    
    # Collect keystream bytes for IVs starting with known patterns
    for iv_num in range(256):
        iv = bytes([0xDD, 0xF0, iv_num & 0xFF])  # Weak IV pattern in WEP
        effective_key = iv + root_key
        
        state = _ksa(effective_key)
        keystream_byte = _prga(state, 1)[0]
        keystream_samples.append((iv, keystream_byte))
    
    # Analyze first bytes
    first_bytes = [ks for _, ks in keystream_samples]
    freq = Counter(first_bytes)
    
    print("Keystream byte distribution for weak IVs (first 3 bytes = 0xDDF0xx):")
    print(f"\n{'Byte':<8} {'Count':<8} {'Percentage':<12} {'Distribution'}")
    print("-" * 60)
    
    for byte_val in range(256):
        count = freq.get(byte_val, 0)
        if count > 0:
            percentage = count / len(first_bytes) * 100
            bar = "█" * int(percentage / 2)
            print(f"{byte_val:<8} {count:<8} {percentage:>6.2f}%      {bar}")
    
    print("\nKey Finding:")
    print("  ✓ Certain IV values create bias in keystream distribution")
    print("  ✓ Attacker collects ~1.5 million packets from same router")
    print("  ✓ Analyzes IV/keystream pairs to statistically recover root key")
    print("  ✓ This completely breaks WEP security")
    
    # Show specific weak IVs
    print("\nExample weak IVs that expose key information:")
    for i, (iv, ks) in enumerate(keystream_samples[:5]):
        print(f"  IV {iv.hex()}: keystream byte = {ks:3d} (0x{ks:02x})")


def rc4_statistical_bias_analysis():
    """
    RC4 Statistical Bias Analysis
    
    The second and subsequent bytes of RC4 keystream have documented biases:
    - Byte 2 has bias toward 0
    - This was discovered by Fluhrer and McGrew
    """
    print("\n" + "=" * 70)
    print("RC4 STATISTICAL BIAS: Second Byte Analysis")
    print("=" * 70)
    
    print("\nGenerating keystreams and analyzing second byte distribution...")
    print("(This may take a moment)\n")
    
    second_bytes = []
    num_samples = 10000
    
    for seed in range(num_samples):
        # Create different keys (simulating different packets)
        key = bytes([0x01, 0x02]) + os.urandom(8) + bytes([seed % 256])
        
        state = _ksa(key)
        # Skip first byte, capture second byte
        _ = _prga(state, 1)  # First byte
        second_byte = _prga(state, 1)[0]  # Second byte
        second_bytes.append(second_byte)
    
    freq = Counter(second_bytes)
    
    # Calculate statistics
    byte_0_count = freq.get(0, 0)
    avg_expected = num_samples / 256  # ~39 for 10000 samples
    
    print(f"Results from {num_samples:,} RC4 keystreams:\n")
    print(f"Second byte = 0:    {byte_0_count:4d} occurrences ({byte_0_count/num_samples*100:5.2f}%)")
    print(f"Expected (uniform): {avg_expected:4.0f} occurrences ({100/256:5.2f}%)")
    print(f"Excess bias:        {byte_0_count - avg_expected:4.0f} ({(byte_0_count/avg_expected - 1)*100:5.2f}% above expected)")
    
    print("\nTop 15 most frequent second bytes:")
    print(f"{'Byte':<8} {'Count':<8} {'Percent':<12} {'vs Expected':<15}")
    print("-" * 53)
    
    for byte_val, count in freq.most_common(15):
        percentage = count / num_samples * 100
        expected_pct = 100 / 256
        delta = percentage - expected_pct
        bar = "█" * int(count / num_samples * 50)
        print(f"{byte_val:<8} {count:<8} {percentage:>6.2f}%       {delta:+6.2f}%      {bar}")
    
    print("\n\nWhy this matters:")
    print("  • RFC 7539 (ChaCha20) explicitly cites RC4 bias as reason for replacement")
    print("  • With millions of bytes, an attacker can statistically recover plaintext")
    print("  • This is one of several documented biases in RC4")
    print("  • Complete break of RC4 in TLS was demonstrated by Mantin & Shamir")


def rc4_keystream_correlation():
    """
    Show correlation between key bytes and early keystream bytes
    
    Early keystream bytes have correlation with key bytes,
    allowing partial key recovery in some scenarios.
    """
    print("\n" + "=" * 70)
    print("RC4 KEY-KEYSTREAM CORRELATION")
    print("=" * 70)
    
    print("\nKey schedules from different keys and their first 8 keystream bytes:\n")
    
    test_keys = [
        b"KEY1",
        b"KEY2",
        b"KEY3",
        b"AAAA",
        b"BBBB",
    ]
    
    print(f"{'Key':<16} First 8 Keystream Bytes")
    print(f"{'-'*16} {'-'*48}")
    
    for key in test_keys:
        state = _ksa(key)
        keystream = _prga(state, 8)
        ks_hex = ' '.join(f'{b:02x}' for b in keystream)
        print(f"{str(key):<16} {ks_hex}")
    
    print("\n\nKey Finding:")
    print("  • Similar keys can produce related keystreams")
    print("  • This violates the independence requirement of stream ciphers")
    print("  • Attacker can sometimes distinguish RC4 from random output")
    print("  • With enough samples, suggests patterns in key scheduling")


def rc4_known_plaintext_attack_demo():
    """
    If plaintext and ciphertext are known, and RC4 IV is known,
    the keystream is directly recovered, showing cipher flexibility.
    """
    print("\n" + "=" * 70)
    print("RC4 KNOWN PLAINTEXT ATTACK")
    print("=" * 70)
    
    plaintext = b"This is a secret message"
    key = b"SecretKey"
    
    # Encrypt
    state = _ksa(key)
    ciphertext = bytes(p ^ c for p, c in zip(plaintext, _prga(state, len(plaintext))))
    
    print(f"\nScenario: Attacker knows plaintext and ciphertext (both transmitted in clear)")
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}\n")
    
    # Attack: Recover keystream
    recovered_keystream = bytes(p ^ c for p, c in zip(plaintext, ciphertext))
    
    print(f"Recovered keystream: {recovered_keystream.hex()}")
    print(f"\nNow attacker has:")
    print(f"  • The keystream for this IV")
    print(f"  • Can reuse this keystream on other messages with SAME key+IV")
    print(f"  • Or use this to make assumptions about the key")
    
    # Decrypt different ciphertext with same keystream
    print(f"\nIf attacker intercepts another message with same IV:")
    different_message = b"Hello World!!!!!"
    different_ciphertext = bytes(m ^ k for m, k in zip(different_message, recovered_keystream[:len(different_message)]))
    
    print(f"  New ciphertext: {different_ciphertext.hex()}")
    print(f"  Attacker can recover: {bytes(c ^ k for c, k in zip(different_ciphertext, recovered_keystream[:len(different_ciphertext)]))}")


if __name__ == "__main__":
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 20 + "RC4 VULNERABILITIES AND ATTACKS" + " " * 16 + "║")
    print("╚" + "═" * 68 + "╝")
    
    wep_vulnerability_demo()
    rc4_statistical_bias_analysis()
    rc4_keystream_correlation()
    rc4_known_plaintext_attack_demo()
    
    print("\n" + "=" * 70)
    print("CONCLUSION: RC4 IS COMPLETELY BROKEN")
    print("=" * 70)
    print("""
Documented RC4 Attacks:
  ✗ WEP vulnerability (FMS attack)            - Key recovery from IV patterns
  ✗ Statistical bias                          - Non-uniform keystream distribution
  ✗ Key/IV correlation                        - Reveals information about key
  ✗ Fluhrer-McGrew bias                       - Byte 2 biased toward 0
  ✗ NOMORE attack                             - Exploits non-uniform output
  
Timeline:
  2001: FMS attack breaks WEP
  2004: Multiple biases documented
  2013: RC4-in-TLS attacks intensify
  2015: RFC 7539 bans RC4 from TLS
  2019: RFC 8446 (TLS 1.3) removes RC4 entirely
  
Replacement Algorithms:
  ✓ ChaCha20                                  - No known biases
  ✓ AES-CTR                                   - Proven secure (for now)
  ✓ AES-GCM                                   - Authenticated encryption
    """)
    print("=" * 70 + "\n")
