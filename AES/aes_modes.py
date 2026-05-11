"""
AES (Advanced Encryption Standard / Rijndael) Modes: ECB, CBC, CTR
Vulnerabilities: Nonce reuse, patterns in ECB, avalanche in CBC
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import time


def aes_modes_comparison():
    """
    Compare AES-128 in three modes: ECB, CBC, CTR
    """
    print("\n" + "=" * 70)
    print("AES: ECB vs CBC vs CTR MODES")
    print("=" * 70)
    
    plaintext = b"Sensitive Data that needs encryption!!!!"
    key_128 = get_random_bytes(16)  # 128-bit key
    
    print(f"\nPlaintext ({len(plaintext)} bytes): {plaintext}")
    print(f"Key (16 bytes): {key_128.hex()}\n")
    
    # ECB Mode
    cipher_ecb = AES.new(key_128, AES.MODE_ECB)
    plaintext_padded = pad(plaintext, AES.block_size)
    ciphertext_ecb = cipher_ecb.encrypt(plaintext_padded)
    
    print(f"1. ECB Mode (Electronic Code Book):")
    print(f"   Ciphertext: {ciphertext_ecb.hex()}")
    print(f"   ⚠ WARNING: Identical plaintext blocks produce identical ciphertext blocks!")
    
    # Verify decryption
    cipher_ecb_dec = AES.new(key_128, AES.MODE_ECB)
    decrypted_ecb = unpad(cipher_ecb_dec.decrypt(ciphertext_ecb), AES.block_size)
    print(f"   Decrypted: {decrypted_ecb}")
    print(f"   ✓ Correct: {decrypted_ecb == plaintext}\n")
    
    # CBC Mode
    iv_cbc = get_random_bytes(AES.block_size)
    cipher_cbc = AES.new(key_128, AES.MODE_CBC, iv_cbc)
    ciphertext_cbc = cipher_cbc.encrypt(plaintext_padded)
    
    print(f"2. CBC Mode (Cipher Block Chaining):")
    print(f"   IV: {iv_cbc.hex()}")
    print(f"   Ciphertext: {ciphertext_cbc.hex()}")
    print(f"   ✓ Good: Ciphertext appears random due to chaining")
    
    cipher_cbc_dec = AES.new(key_128, AES.MODE_CBC, iv_cbc)
    decrypted_cbc = unpad(cipher_cbc_dec.decrypt(ciphertext_cbc), AES.block_size)
    print(f"   Decrypted: {decrypted_cbc}")
    print(f"   ✓ Correct: {decrypted_cbc == plaintext}\n")
    
    # CTR Mode (counter mode - stream cipher)
    nonce_ctr = get_random_bytes(AES.block_size // 2)
    cipher_ctr = AES.new(key_128, AES.MODE_CTR, nonce=nonce_ctr)
    ciphertext_ctr = cipher_ctr.encrypt(plaintext)  # No padding needed in CTR
    
    print(f"3. CTR Mode (Counter Mode - Stream Cipher):")
    print(f"   Nonce: {nonce_ctr.hex()}")
    print(f"   Ciphertext: {ciphertext_ctr.hex()}")
    print(f"   ✓ No padding needed, random-looking output")
    
    cipher_ctr_dec = AES.new(key_128, AES.MODE_CTR, nonce=nonce_ctr)
    decrypted_ctr = cipher_ctr_dec.decrypt(ciphertext_ctr)
    print(f"   Decrypted: {decrypted_ctr}")
    print(f"   ✓ Correct: {decrypted_ctr == plaintext}\n")


def aes_key_size_comparison():
    """
    Compare AES-128 vs AES-192 vs AES-256 performance and security
    """
    print("\n" + "=" * 70)
    print("AES: KEY SIZE COMPARISON (128 vs 192 vs 256)")
    print("=" * 70)
    
    plaintext = get_random_bytes(10 * 1024 * 1024)  # 10 MB
    
    print(f"\nBenchmarking AES on {len(plaintext) / 1024 / 1024:.0f} MB of data\n")
    
    configs = [
        ("AES-128", 16, AES.MODE_CBC),
        ("AES-192", 24, AES.MODE_CBC),
        ("AES-256", 32, AES.MODE_CBC),
    ]
    
    print(f"{'Algorithm':<15} {'Key Bits':<12} {'Time (s)':<12} {'Speed (MB/s)':<15} {'Security Level'}")
    print("-" * 80)
    
    for name, key_size, mode in configs:
        key = get_random_bytes(key_size)
        iv = get_random_bytes(AES.block_size)
        
        cipher = AES.new(key, mode, iv)
        
        start = time.time()
        _ = cipher.encrypt(pad(plaintext, AES.block_size))
        elapsed = time.time() - start
        
        speed = len(plaintext) / 1024 / 1024 / elapsed
        security_level = {
            16: "~128-bit",
            24: "~192-bit",
            32: "~256-bit"
        }[key_size]
        
        print(f"{name:<15} {key_size * 8:<12} {elapsed:<12.4f} {speed:<15.2f} {security_level}")
    
    print("\nSecurity Notes:")
    print("  • 2^128 operations to brute force AES-128 (infeasible with current tech)")
    print("  • AES-256 recommended for post-quantum safety margin")
    print("  • Speed difference minimal - use strongest practical key (256-bit)")


def aes_nonce_reuse_vulnerability():
    """
    CRITICAL: CTR Mode Nonce Reuse Vulnerability
    
    If same (key, nonce) pair is used twice:
    C1 = M1 ⊕ keystream
    C2 = M2 ⊕ keystream
    
    Then: C1 ⊕ C2 = M1 ⊕ M2 (keystream cancels!)
    """
    print("\n" + "=" * 70)
    print("AES CTR MODE: NONCE REUSE VULNERABILITY")
    print("=" * 70)
    
    key = get_random_bytes(16)
    nonce = get_random_bytes(8)  # Reused nonce - vulnerability!
    
    message1 = b"ATTACK at DAWN  "  # 16 bytes
    message2 = b"Defense READY!!!"  # 16 bytes
    
    print(f"\nScenario: Same AES key + nonce used for two messages")
    print(f"Key: {key.hex()}")
    print(f"Nonce (REUSED): {nonce.hex()}\n")
    
    # Encrypt with same key+nonce
    cipher1 = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext1 = cipher1.encrypt(message1)
    
    # Attacker reuses same nonce+key (VULNERABILITY!)
    cipher2 = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ciphertext2 = cipher2.encrypt(message2)
    
    print(f"Message 1: {message1}")
    print(f"CT1:       {ciphertext1.hex()}\n")
    
    print(f"Message 2: {message2}")
    print(f"CT2:       {ciphertext2.hex()}\n")
    
    # Attack: XOR the ciphertexts
    xor_ct = bytes(c1 ^ c2 for c1, c2 in zip(ciphertext1, ciphertext2))
    xor_pt = bytes(m1 ^ m2 for m1, m2 in zip(message1, message2))
    
    print(f"ATTACK: Attacker XORs C1 ⊕ C2:")
    print(f"C1 ⊕ C2:   {xor_ct.hex()}")
    print(f"M1 ⊕ M2:   {xor_pt.hex()}")
    print(f"Match: {'✓ YES - VULNERABLE!' if xor_ct == xor_pt else '✗ NO'}\n")
    
    print(f"From M1 ⊕ M2, attacker can:")
    print(f"  • Identify common words/patterns")
    print(f"  • If part of M1 is known, recover M2")
    print(f"  • Build statistical model of plaintexts")
    
    print("\n⚠ WARNING: One nonce reuse = COMPLETE SECURITY FAILURE")
    print("   • Never reuse (key, nonce) pair in CTR mode")
    print("   • Nonce must be random or strictly incrementing")


def aes_cbc_avalanche_effect():
    """
    Demonstrate CBC mode avalanche effect:
    - Change 1 bit in IV
    - See how it propagates through ciphertext
    """
    print("\n" + "=" * 70)
    print("AES CBC MODE: AVALANCHE EFFECT")
    print("=" * 70)
    
    key = get_random_bytes(16)
    plaintext = b"This is sensitive data for CBC mode encryption analysis!!!!"
    plaintext_padded = pad(plaintext, AES.block_size)
    
    # Original IV
    iv1 = get_random_bytes(16)
    cipher1 = AES.new(key, AES.MODE_CBC, iv1)
    ct1 = cipher1.encrypt(plaintext_padded)
    
    # Modified IV (1 bit flipped)
    iv2 = bytearray(iv1)
    iv2[0] ^= 0x01
    iv2 = bytes(iv2)
    
    cipher2 = AES.new(key, AES.MODE_CBC, iv2)
    ct2 = cipher2.encrypt(plaintext_padded)
    
    print(f"\nPlaintext: {plaintext[:40]}...  ({len(plaintext)} bytes)")
    print(f"\nIV 1: {iv1.hex()}")
    print(f"IV 2: {iv2.hex()} (first bit flipped)\n")
    
    # Analyze differences
    print(f"{'Block':<8} {'CT1':<40} {'CT2':<40} {'Diff Bits'}")
    print("-" * 100)
    
    total_diff_bits = 0
    for i in range(0, len(ct1), 16):
        ct1_block = ct1[i:i+16]
        ct2_block = ct2[i:i+16]
        diff_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(ct1_block, ct2_block))
        total_diff_bits += diff_bits
        
        ct1_hex = ct1_block.hex()[:30] + "..."
        ct2_hex = ct2_block.hex()[:30] + "..."
        
        print(f"Block {i//16:<2} {ct1_hex:<40} {ct2_hex:<40} {diff_bits}")
    
    print(f"\nTotal changed bits: {total_diff_bits} / {len(ct1) * 8} ({total_diff_bits / (len(ct1) * 8) * 100:.1f}%)")
    print(f"Expected (avalanche): ~50%\n")
    
    print("Avalanche Property:")
    print("  ✓ Small change in IV causes massive change in ciphertext")
    print("  ✓ This is GOOD for security (one-way function)")
    print("  ✓ Every bit of ciphertext depends on all message bits")


def aes_modes_chosen_ciphertext_attack():
    """
    Demonstrate why ECB is vulnerable to chosen ciphertext attacks
    """
    print("\n" + "=" * 70)
    print("AES ECB: CHOSEN CIPHERTEXT ATTACK")
    print("=" * 70)
    
    key = get_random_bytes(16)
    
    # Secret password (unknown to attacker)
    secret_prefix = b"FLAG{SECRET_123}"  # 16 bytes = 1 block
    attacker_controlled = b"X" * 16
    
    print(f"\nScenario: System encrypts (secret_prefix || attacker_data) in ECB mode")
    print(f"Secret prefix: {secret_prefix} (attacker doesn't know this)\n")
    
    # Oracle function: encrypts secret + attacker input
    def encrypt_oracle(attacker_input):
        plaintext = secret_prefix + attacker_input
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(plaintext, AES.block_size))
    
    # Get ciphertext of secret+padding
    ct_secret_block = encrypt_oracle(b"")[0:16]  # First block of (secret || padding)
    
    print(f"Ciphertext of secret (encrypted): {ct_secret_block.hex()}\n")
    
    # Attack: brute force each byte of secret
    print("Attacking: brute-force the secret byte-by-byte")
    
    recovered_secret = b""
    for byte_pos in range(16):
        print(f"  Finding byte {byte_pos}...", end=" ")
        
        # Try all 256 possible byte values
        for test_byte in range(256):
            test_input = b"X" * (15 - byte_pos) + bytes([test_byte])
            ct = encrypt_oracle(test_input)
            
            if ct[0:16] == ct_secret_block:
                recovered_secret += bytes([test_byte])
                print(f"Found: {chr(test_byte) if 32 <= test_byte < 127 else '?'}")
                break
        else:
            print(f"NOT FOUND")
            return
    
    print(f"\nRecovered secret: {recovered_secret}")
    print(f"Actual secret:   {secret_prefix}")
    print(f"Match: {'✓ YES - COMPLETELY BROKEN!' if recovered_secret == secret_prefix else '✗ NO'}\n")
    
    print("Why ECB failed:")
    print("  • ECB encrypts each block independently")
    print("  • Attacker can build lookup table by querying oracle")
    print("  • With enough oracle access, entire key material leaked")


if __name__ == "__main__":
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "AES (RIJNDAEL): MODES AND VULNERABILITIES" + " " * 12 + "║")
    print("╚" + "═" * 68 + "╝")
    
    aes_modes_comparison()
    aes_key_size_comparison()
    aes_nonce_reuse_vulnerability()
    aes_cbc_avalanche_effect()
    aes_modes_chosen_ciphertext_attack()
    
    print("\n" + "=" * 70)
    print("AES SECURITY SUMMARY")
    print("=" * 70)
    print("""
AES Strengths:
  ✓ No known practical attacks (since 2001)
  ✓ NIST standard, widely deployed
  ✓ 128-bit blocks, 128/192/256-bit keys
  ✓ Hardware acceleration (AES-NI on modern CPUs)
  ✓ Fast: ~3-4 cycles per byte
  
AES Modes:
  ✗ ECB: NEVER USE - pattern leakage
  ✓ CBC: Good with random IV and authentication
  ✓ CTR: Good for streaming, parallel operations
  ✓ GCM: BEST - includes authentication
  
Critical Rules:
  1. ALWAYS use random IV/nonce
  2. NEVER reuse IV/nonce with same key
  3. Always authenticate (use GCM or CBC+MAC)
  4. Never use ECB mode
  
Recommended Use:
  • Confidential data: AES-256-GCM (authenticated encryption)
  • Legacy systems: AES-128-CBC with HMAC
  • High-performance: AES-256-CTR (but add authentication layer)
    """)
    print("=" * 70 + "\n")
