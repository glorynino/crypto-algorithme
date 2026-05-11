"""
MD5 (Message Digest 5) Implementation
WARNING: MD5 is broken for cryptographic purposes. Use SHA-256 or better instead.
This is for educational purposes only.
"""

import struct


# MD5 constants
S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
]

K = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]


def _f(x, y, z):
    return (x & y) | (~x & z)


def _g(x, y, z):
    return (x & z) | (y & ~z)


def _h(x, y, z):
    return x ^ y ^ z


def _i(x, y, z):
    return y ^ (x | ~z)


def _rotate_left(x, n):
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def md5(data):
    """Compute MD5 hash of data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Initialize MD5 state
    a0 = 0x67452301
    b0 = 0xefcdab89
    c0 = 0x98badcfe
    d0 = 0x10325476
    
    # Pre-processing
    msg = bytearray(data)
    msg_len = len(data)
    msg.append(0x80)
    
    while (len(msg) % 64) != 56:
        msg.append(0x00)
    
    # Append length in bits (little-endian)
    msg.extend(struct.pack('<Q', msg_len * 8))
    
    # Process message in 512-bit chunks
    for chunk_start in range(0, len(msg), 64):
        chunk = msg[chunk_start:chunk_start + 64]
        x = list(struct.unpack('<16I', chunk))
        
        aa, bb, cc, dd = a0, b0, c0, d0
        
        for i in range(64):
            if i < 16:
                f_val = _f(bb, cc, dd)
                g_val = i
            elif i < 32:
                f_val = _g(bb, cc, dd)
                g_val = (5 * i + 1) % 16
            elif i < 48:
                f_val = _h(bb, cc, dd)
                g_val = (3 * i + 5) % 16
            else:
                f_val = _i(bb, cc, dd)
                g_val = (7 * i) % 16
            
            temp = dd
            dd = cc
            cc = bb
            bb = (bb + _rotate_left((aa + f_val + K[i] + x[g_val]) & 0xffffffff, S[i])) & 0xffffffff
            aa = temp
        
        a0 = (a0 + aa) & 0xffffffff
        b0 = (b0 + bb) & 0xffffffff
        c0 = (c0 + cc) & 0xffffffff
        d0 = (d0 + dd) & 0xffffffff
    
    # Produce the final hash value (little-endian)
    return struct.pack('<4I', a0, b0, c0, d0).hex()


def md5_str(data):
    """Return MD5 hash as hex string."""
    return md5(data)


if __name__ == "__main__":
    import hashlib
    
    test_data = [
        b"",
        b"a",
        b"abc",
        b"message digest",
        b"abcdefghijklmnopqrstuvwxyz",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    ]
    
    print("MD5 Implementation Test (Educational)")
    print("=" * 60)
    
    for data in test_data:
        impl_hash = md5(data)
        lib_hash = hashlib.md5(data).hexdigest()
        match = "✓" if impl_hash == lib_hash else "✗"
        print(f"{match} Input: {data[:40]}")
        print(f"  Custom:   {impl_hash}")
        print(f"  Library:  {lib_hash}")
        print()
