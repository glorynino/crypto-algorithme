"""
File Integrity Verification
Demonstrates practical use of SHA-256 for file verification
"""

import hashlib
import os


def compute_file_hash(file_path, algorithm='sha256'):
    """Compute hash of a file."""
    hash_obj = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_obj.update(chunk)
    
    return hash_obj.hexdigest()


def verify_file_integrity(file_path, expected_hash, algorithm='sha256'):
    """Verify file hasn't been modified (checksum verification)."""
    computed_hash = compute_file_hash(file_path, algorithm)
    return computed_hash == expected_hash.lower()


def create_test_file():
    """Create a test file."""
    test_file = "/tmp/test_integrity.txt"
    with open(test_file, 'w') as f:
        f.write("This is a test file for integrity verification.\n")
        f.write("Linux kernel image content simulation.\n")
        f.write("If this file is modified, the hash will change.\n")
    return test_file


def file_integrity_demo():
    """Demonstrate file integrity checking."""
    
    print("\n" + "=" * 70)
    print("FILE INTEGRITY VERIFICATION (SHA-256)")
    print("=" * 70)
    
    # Create test file
    test_file = create_test_file()
    
    # Compute original hash
    original_hash = compute_file_hash(test_file, 'sha256')
    print(f"\nFile: {test_file}")
    print(f"Original SHA-256: {original_hash}")
    
    # Verify integrity (should pass)
    print("\n1. Verifying original file...")
    is_valid = verify_file_integrity(test_file, original_hash, 'sha256')
    print(f"   Status: {'✓ OK' if is_valid else '✗ CORRUPTED'}")
    
    # Modify file slightly
    print("\n2. Modifying file...")
    with open(test_file, 'a') as f:
        f.write("This line was added later.\n")
    
    modified_hash = compute_file_hash(test_file, 'sha256')
    print(f"   Modified SHA-256: {modified_hash}")
    
    # Verify against original hash (should fail)
    is_valid = verify_file_integrity(test_file, original_hash, 'sha256')
    print(f"   Against original: {'✓ OK' if is_valid else '✗ CORRUPTED'}")
    
    # Show bit difference
    bit_diff = 0
    for h1, h2 in zip(bytes.fromhex(original_hash), bytes.fromhex(modified_hash)):
        bit_diff += bin(h1 ^ h2).count('1')
    
    print(f"\n3. Avalanche effect:")
    print(f"   Bit differences: {bit_diff} out of {len(original_hash)*4}")
    print(f"   Flip rate: {(bit_diff / (len(original_hash)*4)) * 100:.1f}%")
    
    # Cleanup
    os.remove(test_file)
    
    return original_hash != modified_hash


def hmac_example():
    """Demonstrate HMAC for authenticated hashing."""
    import hmac
    
    print("\n" + "=" * 70)
    print("HMAC (Hash-based Message Authentication Code)")
    print("=" * 70)
    
    message = b"Important data that needs authentication"
    secret_key = b"super_secret_key_12345"
    
    # Create HMAC
    h = hmac.new(secret_key, message, hashlib.sha256)
    hmac_value = h.hexdigest()
    
    print(f"\nMessage: {message}")
    print(f"Secret key: {secret_key}")
    print(f"HMAC-SHA256: {hmac_value}")
    
    # Verify HMAC
    h_verify = hmac.new(secret_key, message, hashlib.sha256)
    is_valid = hmac.compare_digest(h.digest(), h_verify.digest())
    print(f"Verification: {'✓ VALID' if is_valid else '✗ INVALID'}")
    
    # Modify message
    modified_message = b"Important data that needs authentication (modified)"
    h_modified = hmac.new(secret_key, modified_message, hashlib.sha256)
    is_valid = hmac.compare_digest(h.digest(), h_modified.digest())
    print(f"\nModified message verification: {'✓ VALID' if is_valid else '✗ INVALID'}")


if __name__ == "__main__":
    file_integrity_demo()
    hmac_example()
