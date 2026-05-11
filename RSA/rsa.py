"""
RSA Cryptosystem - Educational Implementation
Textbook RSA encryption and signature (INSECURE without padding!)
"""

import random
from math import gcd


def extended_gcd(a, b):
    """Extended Euclidean algorithm"""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse(a, m):
    """Compute a^-1 mod m"""
    gcd_val, x, _ = extended_gcd(a % m, m)
    if gcd_val != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m


def is_prime(n, k=10):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    """Generate random prime of given bit length"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Set MSB and LSB
        if is_prime(num):
            return num


class RSAKey:
    """RSA Key (public or private)"""
    
    def __init__(self, n, e, d=None):
        """
        Args:
            n: Modulus (product of two primes p, q)
            e: Public exponent
            d: Private exponent (None if public key only)
        """
        self.n = n
        self.e = e
        self.d = d  # None for public key
    
    def is_private(self):
        return self.d is not None
    
    def encrypt(self, plaintext):
        """Encrypt plaintext (textbook RSA - insecure!)"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        plaintext_int = int.from_bytes(plaintext, 'big')
        if plaintext_int >= self.n:
            raise ValueError("Plaintext too large")
        return pow(plaintext_int, self.e, self.n)
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext (requires private key)"""
        if not self.is_private():
            raise ValueError("Private key required")
        plaintext_int = pow(ciphertext, self.d, self.n)
        return plaintext_int
    
    def sign(self, message):
        """Create signature (textbook RSA - insecure!)"""
        if not self.is_private():
            raise ValueError("Private key required")
        if isinstance(message, str):
            message = message.encode()
        message_int = int.from_bytes(message, 'big')
        if message_int >= self.n:
            raise ValueError("Message too large")
        return pow(message_int, self.d, self.n)
    
    def verify(self, signature, message):
        """Verify signature"""
        if isinstance(message, str):
            message = message.encode()
        message_int = int.from_bytes(message, 'big')
        recovered = pow(signature, self.e, self.n)
        return recovered == message_int
    
    def __repr__(self):
        if self.is_private():
            return f"RSAPrivateKey(n={self.n.bit_length()}-bit, e={self.e})"
        else:
            return f"RSAPublicKey(n={self. bit_length()}-bit, e={self.e})"


def generate_keypair(key_bits=512):
    """
    Generate RSA keypair
    
    Args:
        key_bits: Bit length of modulus n
        
    Returns:
        (public_key, private_key) tuple
    """
    # Generate two large distinct primes
    p = generate_prime(key_bits // 2)
    q = generate_prime(key_bits // 2)
    
    while p == q:
        q = generate_prime(key_bits // 2)
    
    # Compute modulus
    n = p * q
    
    # Compute Euler's totient
    phi = (p - 1) * (q - 1)
    
    # Choose public exponent (usually 65537)
    e = 65537
    if gcd(e, phi) != 1:
        # Find coprime e
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    
    # Compute private exponent
    d = mod_inverse(e, phi)
    
    # Create key objects
    public_key = RSAKey(n, e)
    private_key = RSAKey(n, e, d)
    
    return public_key, private_key


def test_rsa():
    """Test basic RSA encryption"""
    print("\n" + "=" * 70)
    print("BASIC RSA TEST")
    print("=" * 70 + "\n")
    
    print("Generating 1024-bit RSA keypair...")
    pub, priv = generate_keypair(1024)
    
    print(f"✓ Generated")
    print(f"  Modulus: {pub.n.bit_length()}-bit")
    print(f"  Public exponent: {pub.e}")
    print(f"  Private exponent: {priv.d.bit_length()}-bit\n")
    
    # Encryption test
    plaintext = b"SECRET"
    print(f"Plaintext: {plaintext}")
    ciphertext = pub.encrypt(plaintext)
    print(f"Ciphertext: {ciphertext}\n")
    
    # Decryption test
    recovered = priv.decrypt(ciphertext)
    print(f"Decrypted: {recovered}")
    print(f"Match: {recovered == int.from_bytes(plaintext, 'big')} ✓\n")
    
    # Signature test
    message = b"SIGN ME"
    print(f"Message: {message}")
    signature = priv.sign(message)
    print(f"Signature: {signature}\n")
    
    valid = pub.verify(signature, message)
    print(f"Signature valid: {valid} ✓\n")


if __name__ == "__main__":
    test_rsa()
    print("=" * 70)
