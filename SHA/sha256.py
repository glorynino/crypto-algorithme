"""
SHA-256 (Secure Hash Algorithm 256-bit) Implementation
Modern cryptographic hash function used in TLS, Git, Bitcoin, JWT
"""

import struct


# SHA-256 constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def _right_rotate(x, n):
    """Right rotate 32-bit integer."""
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def _sha256_ch(x, y, z):
    return (x & y) ^ (~x & z)


def _sha256_maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def _sha256_sum0(x):
    return _right_rotate(x, 2) ^ _right_rotate(x, 13) ^ _right_rotate(x, 22)


def _sha256_sum1(x):
    return _right_rotate(x, 6) ^ _right_rotate(x, 11) ^ _right_rotate(x, 25)


def _sha256_sig0(x):
    return _right_rotate(x, 7) ^ _right_rotate(x, 18) ^ (x >> 3)


def _sha256_sig1(x):
    return _right_rotate(x, 17) ^ _right_rotate(x, 19) ^ (x >> 10)


def sha256(data):
    """Compute SHA-256 hash of data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Initialize hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    # Pre-processing
    msg = bytearray(data)
    msg_len = len(data)
    msg.append(0x80)
    
    while (len(msg) % 64) != 56:
        msg.append(0x00)
    
    # Append length in bits (big-endian)
    msg.extend(struct.pack('>Q', msg_len * 8))
    
    # Process message in 512-bit chunks
    for chunk_start in range(0, len(msg), 64):
        chunk = msg[chunk_start:chunk_start + 64]
        w = list(struct.unpack('>16I', chunk))
        
        # Message schedule extension
        for i in range(16, 64):
            s0 = _sha256_sig0(w[i - 15])
            s1 = _sha256_sig1(w[i - 2])
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)
        
        # Working variables
        a, b, c, d, e, f, g, h_val = h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
        
        # Compression function main loop
        for i in range(64):
            S1 = _sha256_sum1(e)
            ch = _sha256_ch(e, f, g)
            temp1 = (h_val + S1 + ch + K[i] + w[i]) & 0xffffffff
            S0 = _sha256_sum0(a)
            maj = _sha256_maj(a, b, c)
            temp2 = (S0 + maj) & 0xffffffff
            
            h_val = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff
        
        # Add compressed chunk to current hash value
        h[0] = (h[0] + a) & 0xffffffff
        h[1] = (h[1] + b) & 0xffffffff
        h[2] = (h[2] + c) & 0xffffffff
        h[3] = (h[3] + d) & 0xffffffff
        h[4] = (h[4] + e) & 0xffffffff
        h[5] = (h[5] + f) & 0xffffffff
        h[6] = (h[6] + g) & 0xffffffff
        h[7] = (h[7] + h_val) & 0xffffffff
    
    # Produce the final hash value (big-endian)
    return struct.pack('>8I', *h).hex()


def sha256_str(data):
    """Return SHA-256 hash as hex string."""
    return sha256(data)


if __name__ == "__main__":
    import hashlib
    
    test_data = [
        b"",
        b"abc",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        b"a" * 1000000,
    ]
    
    print("SHA-256 Implementation Test")
    print("=" * 60)
    
    for data in test_data:
        impl_hash = sha256(data)
        lib_hash = hashlib.sha256(data).hexdigest()
        match = "✓" if impl_hash == lib_hash else "✗"
        data_display = data[:40] if len(data) <= 40 else f"{data[:37]}..."
        print(f"{match} Input: {data_display}")
        print(f"  Custom:   {impl_hash}")
        print(f"  Library:  {lib_hash}")
        print()
