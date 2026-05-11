"""
DES and Triple-DES Implementation with ECB and CBC modes
Using Crypto.Cipher from pycryptodome for low-level block cipher operations
"""

from Crypto.Cipher import DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from io import BytesIO
import time


def des_ecb_cbc_comparison():
    """
    Compare DES in ECB vs CBC modes
    - ECB: Electronic Code Book (insecure - same plaintext blocks → same ciphertext blocks)
    - CBC: Cipher Block Chaining (secure - ciphertext blocks depend on all previous blocks)
    """
    print("\n" + "=" * 70)
    print("DES: ECB vs CBC MODE COMPARISON")
    print("=" * 70)
    
    plaintext = b"Hello World!!!!!"  # 16 bytes = 2 DES blocks
    key = get_random_bytes(8)  # DES uses 8-byte (64-bit) keys
    
    print(f"\nPlaintext ({len(plaintext)} bytes): {plaintext}")
    print(f"Key (8 bytes): {key.hex()}\n")
    
    # ECB Mode
    cipher_ecb = DES.new(key, DES.MODE_ECB)
    padded_plaintext = pad(plaintext, DES.block_size)
    ciphertext_ecb = cipher_ecb.encrypt(padded_plaintext)
    
    print(f"ECB Mode:")
    print(f"  Ciphertext: {ciphertext_ecb.hex()}")
    print(f"  Structure: {' '.join(ciphertext_ecb[i:i+8].hex() for i in range(0, len(ciphertext_ecb), 8))}")
    
    # Decrypt ECB
    cipher_ecb_dec = DES.new(key, DES.MODE_ECB)
    decrypted_ecb = unpad(cipher_ecb_dec.decrypt(ciphertext_ecb), DES.block_size)
    print(f"  Decrypted: {decrypted_ecb}")
    print(f"  Correct: {'✓ YES' if decrypted_ecb == plaintext else '✗ NO'}\n")
    
    # CBC Mode
    iv = get_random_bytes(DES.block_size)
    cipher_cbc = DES.new(key, DES.MODE_CBC, iv)
    ciphertext_cbc = cipher_cbc.encrypt(padded_plaintext)
    
    print(f"CBC Mode (IV: {iv.hex()}):")
    print(f"  Ciphertext: {ciphertext_cbc.hex()}")
    print(f"  Structure: {' '.join(ciphertext_cbc[i:i+8].hex() for i in range(0, len(ciphertext_cbc), 8))}")
    
    # Decrypt CBC
    cipher_cbc_dec = DES.new(key, DES.MODE_CBC, iv)
    decrypted_cbc = unpad(cipher_cbc_dec.decrypt(ciphertext_cbc), DES.block_size)
    print(f"  Decrypted: {decrypted_cbc}")
    print(f"  Correct: {'✓ YES' if decrypted_cbc == plaintext else '✗ NO'}\n")
    
    # Compare
    print("Comparison:")
    print(f"  ECB ciphertext: {ciphertext_ecb.hex()}")
    print(f"  CBC ciphertext: {ciphertext_cbc.hex()}")
    print(f"  Same? {'✗ NO (Good!)' if ciphertext_ecb != ciphertext_cbc else '✓ YES (Bad!)'}")


def des_ecb_weakness_visualization():
    """
    Show ECB mode weakness: identical plaintext blocks produce identical ciphertext blocks
    This leaks information about the plaintext structure.
    """
    print("\n" + "=" * 70)
    print("DES ECB WEAKNESS: Pattern Preservation")
    print("=" * 70)
    
    # Create a simple repeating pattern
    plaintext = b"A" * 64  # 8 blocks of "A"
    key = get_random_bytes(8)
    
    print(f"\nPlaintext: {len(plaintext)} bytes of 'A' (highly repetitive)")
    
    # ECB: all "A" blocks encrypt to same ciphertext
    cipher_ecb = DES.new(key, DES.MODE_ECB)
    ciphertext_ecb = cipher_ecb.encrypt(plaintext)
    
    print(f"\nECB Ciphertext (blocks should be identical):")
    for i in range(0, len(ciphertext_ecb), 8):
        print(f"  Block {i//8}: {ciphertext_ecb[i:i+8].hex()}")
    
    print(f"\nIdentical blocks? {'✓ YES (VULNERABILITY!)' if len(set(ciphertext_ecb[i:i+8] for i in range(0, len(ciphertext_ecb), 8))) == 1 else '✗ NO'}\n")
    
    # CBC: all blocks should be different due to chaining
    iv = get_random_bytes(DES.block_size)
    cipher_cbc = DES.new(key, DES.MODE_CBC, iv)
    ciphertext_cbc = cipher_cbc.encrypt(plaintext)
    
    print(f"CBC Ciphertext (IV: {iv.hex()}):")
    for i in range(0, len(ciphertext_cbc), 8):
        print(f"  Block {i//8}: {ciphertext_cbc[i:i+8].hex()}")
    
    print(f"\nIdentical blocks? {'✗ NO (Good!)' if len(set(ciphertext_cbc[i:i+8] for i in range(0, len(ciphertext_cbc), 8))) > 1 else '✓ YES (Bad!)'}")


def triple_des_performance():
    """
    Triple DES: Apply DES three times (K1, K2, K1)
    Effective key length: 112 bits (or 168 if using 3 different keys)
    """
    print("\n" + "=" * 70)
    print("TRIPLE DES (3DES) PERFORMANCE ANALYSIS")
    print("=" * 70)
    
    # Generate keys
    key_24 = get_random_bytes(24)  # 3 × 8 bytes for 3DES-3KEY
    key_16 = key_24[:16]  # First 16 bytes for 3DES-2KEY
    
    plaintext = get_random_bytes(1024 * 1024)  # 1 MB data
    
    print(f"\nBenchmarking on {len(plaintext) / 1024 / 1024:.1f} MB of data\n")
    
    # DES-ECB (single pass)
    key_8 = key_24[:8]
    cipher = DES.new(key_8, DES.MODE_ECB)
    start = time.time()
    ciphertext_des = cipher.encrypt(plaintext)
    des_time = time.time() - start
    des_speed = len(plaintext) / 1024 / 1024 / des_time
    
    print(f"DES (single):")
    print(f"  Time: {des_time:.4f}s")
    print(f"  Speed: {des_speed:.2f} MB/s\n")
    
    # Triple DES (3 passes)
    cipher = DES3.new(key_24, DES3.MODE_ECB)
    start = time.time()
    ciphertext_3des = cipher.encrypt(plaintext)
    tres_time = time.time() - start
    tres_speed = len(plaintext) / 1024 / 1024 / tres_time
    
    print(f"Triple DES (3-key):")
    print(f"  Time: {tres_time:.4f}s")
    print(f"  Speed: {tres_speed:.2f} MB/s\n")
    
    print(f"Comparison:")
    print(f"  Slowdown: {tres_time / des_time:.2f}x (expected ~3x)")
    print(f"  Speed ratio: {des_speed / tres_speed:.2f}x")
    
    print("\nNote:")
    print("  ✗ DES is now broken (key space too small: 2^56)")
    print("  ✗ 3DES is slow but still used for legacy systems")
    print("  ✓ AES is faster and more secure (next section)")


def des_cbc_iv_sensitivity():
    """
    Demonstrate CBC mode's IV sensitivity:
    - Flipping one bit in IV affects entire first block
    - Error propagates through ciphertext
    """
    print("\n" + "=" * 70)
    print("DES CBC: IV SENSITIVITY (Avalanche Effect)")
    print("=" * 70)
    
    plaintext = b"This is test data for CBC mode IV sensitivity!!!!"
    key = get_random_bytes(8)
    
    # Normal IV
    iv1 = get_random_bytes(DES.block_size)
    cipher1 = DES.new(key, DES.MODE_CBC, iv1)
    plaintext_padded = pad(plaintext, DES.block_size)
    ciphertext1 = cipher1.encrypt(plaintext_padded)
    
    # Modified IV (flip one bit)
    iv2 = bytearray(iv1)
    iv2[0] ^= 0x01  # Flip first bit
    iv2 = bytes(iv2)
    
    cipher2 = DES.new(key, DES.MODE_CBC, iv2)
    ciphertext2 = cipher2.encrypt(plaintext_padded)
    
    print(f"\nIV 1: {iv1.hex()}")
    print(f"IV 2: {iv2.hex()} (1 bit flipped)\n")
    
    # Compare ciphertexts
    differences = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(ciphertext1, ciphertext2))
    changed_bytes = sum(1 for b1, b2 in zip(ciphertext1, ciphertext2) if b1 != b2)
    
    print(f"Ciphertext length: {len(ciphertext1)} bytes")
    print(f"Changed bytes: {changed_bytes}")
    print(f"Changed bits: {differences}\n")
    
    print("First block comparison:")
    print(f"  CT1[0:8]: {ciphertext1[0:8].hex()}")
    print(f"  CT2[0:8]: {ciphertext2[0:8].hex()}")
    print(f"  Completely different (due to IV)?  {'✓ YES' if ciphertext1[0:8] != ciphertext2[0:8] else '✗ NO'}\n")
    
    print("Block-by-block differences:")
    for i in range(0, len(ciphertext1), 8):
        diff_bits = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(ciphertext1[i:i+8], ciphertext2[i:i+8]))
        print(f"  Block {i//8}: {diff_bits:2d} bits different")


if __name__ == "__main__":
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 15 + "DES AND TRIPLE-DES: MODES AND VULNERABILITIES" + " " * 8 + "║")
    print("╚" + "═" * 68 + "╝")
    
    des_ecb_cbc_comparison()
    des_ecb_weakness_visualization()
    des_cbc_iv_sensitivity()
    triple_des_performance()
    
    print("\n" + "=" * 70)
    print("SUMMARY: DES IS DEPRECATED")
    print("=" * 70)
    print("""
DES Vulnerabilities:
  ✗ Key space: 56 bits (2^56 keys) - breakable by brute force
  ✗ Block size: 64 bits - leads to collisions with large data
  ✗ ECB mode: Identical plaintext blocks → identical ciphertext blocks
  ✗ Weak S-boxes: Historical concerns (though not practically exploited)

Triple DES (3DES):
  ✓ Increases effective key strength (168 bits with 3 different keys)
  ✗ Slow: 3x slower than DES (hence 9x slower than AES)
  ✗ Still uses 64-bit blocks

Modern Replacement: AES
  ✓ 128, 192, or 256-bit keys
  ✓ 128-bit blocks
  ✓ Faster (hardware acceleration available)
  ✓ No known practical attacks
  ✓ NIST standard since 2001
  
Modes Recommendation:
  ✓ CBC: Good for general use (with random IV)
  ✓ CTR: Good for parallel encryption / streaming
  ✓ GCM: Best (includes authentication)
  ✗ ECB: NEVER USE (information leakage)
    """)
    print("=" * 70 + "\n")
