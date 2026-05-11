"""
Hash Functions Analysis & Attacks
Demonstrates avalanche effect, collision resistance, and performance
"""

import hashlib
import time
import random
import struct
from MD5.md5 import md5_str
from SHA.sha256 import sha256_str


def avalanche_test(hash_func, data, func_name):
    """Test avalanche effect: 1-bit change should flip ~50% of output bits."""
    
    print(f"\n{func_name} - Avalanche Effect Test")
    print("=" * 70)
    
    # Get original hash
    original_hash = hash_func(data).encode() if isinstance(hash_func(data), str) else hash_func(data)
    if isinstance(original_hash, str):
        original_hash = bytes.fromhex(original_hash)
    
    results = []
    
    for bit_pos in range(len(data) * 8):
        # Flip one bit
        data_arr = bytearray(data)
        byte_pos = bit_pos // 8
        bit_in_byte = bit_pos % 8
        data_arr[byte_pos] ^= (1 << bit_in_byte)
        
        modified_hash = hash_func(bytes(data_arr))
        if isinstance(modified_hash, str):
            modified_hash = bytes.fromhex(modified_hash)
        
        # Count bit differences
        bit_diff = 0
        for h1, h2 in zip(original_hash, modified_hash):
            bit_diff += bin(h1 ^ h2).count('1')
        
        total_bits = len(original_hash) * 8
        flip_rate = (bit_diff / total_bits) * 100
        results.append(flip_rate)
    
    avg_flip = sum(results) / len(results)
    print(f"Original data:  {data[:40]}")
    print(f"Output size:    {len(original_hash)*8} bits")
    print(f"Tests run:      {len(results)}")
    print(f"Average bit flip rate: {avg_flip:.2f}% (ideal: ~50%)")
    print(f"Min/Max:        {min(results):.2f}% / {max(results):.2f}%")
    
    return avg_flip


def hash_comparison(data):
    """Compare MD5, SHA-256, SHA-512 on same input."""
    
    print("\n" + "=" * 70)
    print("Hash Function Comparison")
    print("=" * 70)
    
    print(f"\nInput: {data[:50]}")
    print(f"Size: {len(data)} bytes\n")
    
    hashes = {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
        "SHA-512": hashlib.sha512(data).hexdigest(),
    }
    
    for name, hash_val in hashes.items():
        bits = len(hash_val) * 4
        print(f"{name:10} ({bits:>3} bits): {hash_val[:40]}...")
    
    return hashes


def performance_benchmark(data_sizes=[1e6, 10e6, 100e6]):
    """Benchmark hash functions on different data sizes."""
    
    print("\n" + "=" * 70)
    print("Performance Benchmark")
    print("=" * 70)
    print(f"{'Algorithm':<15} {'Size':>10} {'Time (s)':>10} {'Throughput':>12}")
    print("-" * 50)
    
    for size in data_sizes:
        data = os.urandom(int(size))
        
        for name, hash_func in [("MD5", hashlib.md5), 
                                 ("SHA-256", hashlib.sha256),
                                 ("SHA-512", hashlib.sha512)]:
            start = time.time()
            result = hash_func(data).hexdigest()
            elapsed = time.time() - start
            
            throughput = size / elapsed / 1e6  # MB/s
            print(f"{name:<15} {size/1e6:>7.0f} MB {elapsed:>9.3f}s {throughput:>10.1f} MB/s")
        print()


def collision_resistance_demo():
    """Demonstrate collision resistance properties."""
    
    print("\n" + "=" * 70)
    print("Collision Resistance Analysis")
    print("=" * 70)
    
    # Birthday paradox simulation
    print("\nBirthday Paradox: Expected collisions for n random messages")
    print("Algorithm | Output Bits | Messages for 50% collision probability")
    print("-" * 65)
    
    # Using birthday paradox: n ≈ sqrt(2^k) where k = output bits
    for name, bits in [("MD5", 128), ("SHA-256", 256), ("SHA-512", 512)]:
        n = int((2 ** (bits/2)))
        print(f"{name:>9} | {bits:>11} | ~2^{bits//2} (~{n:.2e}) messages")
    
    print("\nMD5 Status: BROKEN (collisions found)")
    print("SHA-256: STRONG (no collisions known)")
    print("SHA-512: STRONG (no collisions known)")


def find_bit_patterns(iterations=1000):
    """Find bit patterns in hash outputs (statistical test)."""
    
    print("\n" + "=" * 70)
    print("Statistical Distribution Test")
    print("=" * 70)
    
    for name, hash_func in [("SHA-256", hashlib.sha256),
                             ("SHA-512", hashlib.sha512)]:
        zeros = 0
        ones = 0
        
        for i in range(iterations):
            data = f"test{i}".encode()
            hash_val = hash_func(data).hexdigest()
            
            for char in hash_val:
                bits = bin(int(char, 16))[2:].zfill(4)
                zeros += bits.count('0')
                ones += bits.count('1')
        
        total = zeros + ones
        zero_pct = (zeros / total) * 100
        one_pct = (ones / total) * 100
        
        print(f"\n{name} after {iterations} iterations:")
        print(f"  Zeros: {zero_pct:.2f}% (ideal: 50%)")
        print(f"  Ones:  {one_pct:.2f}% (ideal: 50%)")


if __name__ == "__main__":
    import os
    
    # Test data
    test_msg = b"The quick brown fox jumps over the lazy dog"
    
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "TP 4 - HASH FUNCTIONS ANALYSIS & ATTACKS".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "=" * 68 + "╝")
    
    # Test avalanche for each algorithm
    avalanche_test(hashlib.md5, test_msg, "MD5")
    avalanche_test(hashlib.sha256, test_msg, "SHA-256")
    avalanche_test(hashlib.sha512, test_msg, "SHA-512")
    
    # Compare hash functions
    hash_comparison(test_msg)
    
    # Performance benchmark
    try:
        performance_benchmark([1e6, 10e6])
    except Exception as e:
        print(f"Benchmark skipped: {e}")
    
    # Collision resistance analysis
    collision_resistance_demo()
    
    # Statistical distribution
    find_bit_patterns(100)
    
    print("\n" + "=" * 70)
    print("✓ Hash Functions Analysis Complete")
    print("=" * 70)
