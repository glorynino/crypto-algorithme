"""Hill cipher known-plaintext attack."""

from sympy import Matrix, mod_inverse

ALPHABET_SIZE = 26
ALPHABET_START = ord("A")


def text_to_vector(text):
    """Convert text to numeric vector (A=0, B=1, ..., Z=25)."""
    return [ord(c.upper()) - ALPHABET_START for c in text if c.isalpha()]


def vector_to_text(vector):
    """Convert numeric vector back to text."""
    return ''.join(chr(int(v) % ALPHABET_SIZE + ALPHABET_START) for v in vector)


def known_plaintext_attack_hill(plaintext, ciphertext, block_size=2):
    """
    Known-plaintext attack on Hill cipher.
    
    Given: 
    - plaintext (known message)
    - ciphertext (corresponding encrypted message)
    - block_size (2 for 2x2, 3 for 3x3, etc.)
    
    This attack recovers the key matrix K by solving: C = K * P (mod 26)
    Therefore: K = C * P^(-1) (mod 26)
    
    Returns: recovered key matrix (as list of lists)
    """
    # Extract only alphabetic characters and convert to vectors
    p_vec = text_to_vector(plaintext)
    c_vec = text_to_vector(ciphertext)
    
    # Need at least block_size blocks to recover the key
    if len(p_vec) < block_size or len(c_vec) < block_size:
        raise ValueError(f"Need at least {block_size} characters in plaintext/ciphertext")
    
    # Extract first block_size chars for each
    p_block = p_vec[:block_size]
    c_block = c_vec[:block_size]
    
    # Create matrices
    P = Matrix(block_size, 1, p_block)
    C = Matrix(block_size, 1, c_block)
    
    # Try to invert P mod 26
    try:
        P_inv = P.inv_mod(ALPHABET_SIZE)
    except ValueError:
        print(f"Plaintext matrix is not invertible mod 26. Trying alternative blocks...")
        # Try with more blocks
        for start in range(0, len(p_vec) - block_size + 1, block_size):
            p_block = p_vec[start:start + block_size]
            c_block = c_vec[start:start + block_size]
            P = Matrix(block_size, 1, p_block)
            C = Matrix(block_size, 1, c_block)
            try:
                P_inv = P.inv_mod(ALPHABET_SIZE)
                break
            except ValueError:
                continue
        else:
            raise ValueError("Could not find invertible plaintext block")
    
    # K = C * P_inv (mod 26)
    K = (C * P_inv).applyfunc(lambda x: int(x) % ALPHABET_SIZE)
    
    return K


def recover_key_matrix_from_blocks(plaintext_blocks, ciphertext_blocks, block_size=2):
    """
    Recover key matrix using multiple plaintext-ciphertext block pairs.
    This is more reliable than single block.
    
    plaintext_blocks: list of plaintext blocks (each of size block_size)
    ciphertext_blocks: list of ciphertext blocks (each of size block_size)
    """
    if len(plaintext_blocks) < block_size:
        raise ValueError(f"Need at least {block_size} plaintext blocks")
    
    # Take first block_size blocks to construct the PT and CT matrices
    p_vectors = []
    c_vectors = []
    
    for i in range(block_size):
        p_vectors.extend(plaintext_blocks[i])
        c_vectors.extend(ciphertext_blocks[i])
    
    P = Matrix(block_size, block_size, p_vectors)
    C = Matrix(block_size, block_size, c_vectors)
    
    # Try to solve K = C * P^(-1) mod 26
    try:
        P_inv = P.inv_mod(ALPHABET_SIZE)
        K = (C * P_inv).applyfunc(lambda x: int(x) % ALPHABET_SIZE)
        return K
    except ValueError as e:
        raise ValueError(f"Plaintext matrix is singular mod 26: {e}")


def verify_key(plaintext, ciphertext, key_matrix, block_size):
    """Verify if the recovered key correctly encrypts plaintext to ciphertext."""
    p_vec = text_to_vector(plaintext)
    c_vec = text_to_vector(ciphertext)
    
    # Encrypt plaintext using key_matrix
    encrypted = []
    for i in range(0, len(p_vec), block_size):
        block = p_vec[i:i+block_size]
        if len(block) < block_size:
            # Pad with 'X'
            block.extend([ord('X') - ALPHABET_START] * (block_size - len(block)))
        
        P = Matrix(block_size, 1, block)
        C_encrypted = (key_matrix * P).applyfunc(lambda x: int(x) % ALPHABET_SIZE)
        encrypted.extend(C_encrypted.T.tolist()[0])
    
    # Compare
    encrypted_text = vector_to_text(encrypted[:len(c_vec)])
    actual_cipher = ''.join(c for c in ciphertext if c.isalpha()).upper()
    
    return encrypted_text == actual_cipher


if __name__ == "__main__":
    print("=" * 70)
    print("HILL CIPHER - KNOWN PLAINTEXT ATTACK")
    print("=" * 70)
    
    # Example 1: 2x2 Hill cipher
    print("\n" + "-" * 70)
    print("EXAMPLE 1: 2x2 Hill Cipher")
    print("-" * 70)
    
    # Original key matrix
    original_key_2x2 = Matrix(2, 2, [5, 8, 17, 3])
    print(f"\nOriginal key matrix (2x2):")
    print(original_key_2x2)
    
    # Test: encrypt a message
    from hill import encrypt_hill
    plaintext = "HILLCIPHER"
    print(f"\nPlaintext:  {plaintext}")
    
    ciphertext = encrypt_hill(plaintext, [[5, 8], [17, 3]])
    print(f"Ciphertext: {ciphertext}")
    
    # Known-plaintext attack
    print(f"\n--- KNOWN-PLAINTEXT ATTACK ---")
    print(f"Attacker knows:")
    print(f"  Plaintext:  {plaintext}")
    print(f"  Ciphertext: {ciphertext}")
    print(f"  Block size: 2 (2x2 key)")
    
    try:
        recovered_key = known_plaintext_attack_hill(plaintext, ciphertext, block_size=2)
        print(f"\nRecovered key matrix:")
        print(recovered_key)
        
        # Verify
        is_correct = verify_key(plaintext, ciphertext, recovered_key, 2)
        print(f"\nKey verification: {'✓ CORRECT' if is_correct else '✗ FAILED'}")
        
        # Try to decrypt with recovered key
        from hill import decrypt_hill
        decrypted = decrypt_hill(ciphertext, [list(recovered_key.row(i)) for i in range(2)])
        print(f"Decrypted:  {decrypted.rstrip('X')}")  # Remove padding
        
    except Exception as e:
        print(f"Error: {e}")
    
    # Example 2: 3x3 Hill cipher
    print("\n" + "-" * 70)
    print("EXAMPLE 2: 3x3 Hill Cipher")
    print("-" * 70)
    
    original_key_3x3 = Matrix(3, 3, [1, 2, 3, 0, 5, 2, 2, 0, 3])
    print(f"\nOriginal key matrix (3x3):")
    print(original_key_3x3)
    
    plaintext_3x3 = "SECRETMESSAGE"
    print(f"\nPlaintext:  {plaintext_3x3}")
    
    ciphertext_3x3 = encrypt_hill(plaintext_3x3, [[1, 2, 3], [0, 5, 2], [2, 0, 3]])
    print(f"Ciphertext: {ciphertext_3x3}")
    
    print(f"\n--- KNOWN-PLAINTEXT ATTACK (3x3) ---")
    try:
        recovered_key_3x3 = known_plaintext_attack_hill(plaintext_3x3, ciphertext_3x3, block_size=3)
        print(f"\nRecovered key matrix:")
        print(recovered_key_3x3)
        
        is_correct_3x3 = verify_key(plaintext_3x3, ciphertext_3x3, recovered_key_3x3, 3)
        print(f"\nKey verification: {'✓ CORRECT' if is_correct_3x3 else '✗ FAILED'}")
        
        decrypted_3x3 = decrypt_hill(ciphertext_3x3, [list(recovered_key_3x3.row(i)) for i in range(3)])
        print(f"Decrypted:  {decrypted_3x3.rstrip('X')}")
        
    except Exception as e:
        print(f"Error: {e}")
    
    # Analysis
    print("\n" + "=" * 70)
    print("SECURITY ANALYSIS")
    print("=" * 70)
    print("""
The Hill cipher is vulnerable to known-plaintext attack because:

1. MATHEMATICAL STRUCTURE: The encryption is linear: C = K * P (mod 26)
   This means if an attacker knows plaintext-ciphertext pairs,
   they can set up a system of linear equations.

2. MATRIX INVERSION: With enough plaintext-ciphertext pairs, an attacker
   can arrange them into invertible matrices and recover K = C * P^(-1).

3. SMALL KEY SPACE: For 2x2 Hill (26^4 = 456,976 keys), or even 3x3
   (26^9 ≈ 5 * 10^12), this is computationally feasible with known pairs.

4. NO DIFFUSION IN TIME: Each plaintext block only depends on that block,
   not on previous blocks. So even short known plaintext leads to key recovery.

COUNTERMEASURES:
- Use very large key matrices (computationally expensive)
- Combine Hill with other ciphers (e.g., Hill + substitution)
- Use modern authenticated encryption instead (AES-GCM, ChaCha20-Poly1305)
    """)
