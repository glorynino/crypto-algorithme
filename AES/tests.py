"""AES-128 Cipher - Unit Tests."""

import unittest
from cipher import AES128
from utils import text_to_bytes, bytes_to_text, pkcs7_pad, pkcs7_unpad


class TestAES128(unittest.TestCase):
    """Test suite for AES-128 cipher."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key = b'0123456789abcdef'  # 16 bytes
        self.cipher = AES128(self.key)
    
    def test_key_initialization(self):
        """Test that cipher initializes with correct key."""
        self.assertEqual(len(self.cipher.round_keys), 11)
        self.assertEqual(len(self.cipher.key), 16)
    
    def test_invalid_key_length(self):
        """Test that invalid key length raises error."""
        with self.assertRaises(ValueError):
            AES128(b'short_key')
        
        with self.assertRaises(ValueError):
            AES128(b'this_is_way_too_long_for_aes128')
    
    def test_encrypt_decrypt_simple(self):
        """Test basic encrypt/decrypt cycle."""
        plaintext = "Hello World!!!!"
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt_text(ciphertext)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_encrypt_decrypt_multiple_blocks(self):
        """Test encryption/decryption with multiple blocks."""
        # 32 bytes = 2 blocks (with padding removed)
        plaintext = "This is a longer message for testing AES encryption and decryption successfully"
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt_text(ciphertext)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_encrypt_empty_string(self):
        """Test encryption of empty string (should produce padded block)."""
        plaintext = ""
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt_text(ciphertext)
        
        self.assertEqual(plaintext, decrypted)
        # Empty string + PKCS7 padding should be 16 bytes
        self.assertEqual(len(ciphertext), 16)
    
    def test_different_keys_produce_different_ciphertexts(self):
        """Test that different keys produce different ciphertexts."""
        plaintext = "Test message"
        
        key1 = b'key1key1key1key1'
        key2 = b'key2key2key2key2'
        
        cipher1 = AES128(key1)
        cipher2 = AES128(key2)
        
        ciphertext1 = cipher1.encrypt(plaintext)
        ciphertext2 = cipher2.encrypt(plaintext)
        
        self.assertNotEqual(ciphertext1, ciphertext2)
    
    def test_same_plaintext_same_ciphertext_ecb(self):
        """Test ECB mode property (same plaintext = same ciphertext)."""
        plaintext = "AAAAAAAAAAAAAAAA"  # 16 bytes, exactly 1 block
        
        ciphertext1 = self.cipher.encrypt(plaintext)
        ciphertext2 = self.cipher.encrypt(plaintext)
        
        self.assertEqual(ciphertext1, ciphertext2)
    
    def test_invalid_ciphertext_length(self):
        """Test that non-multiple of 16 ciphertext raises error."""
        with self.assertRaises(ValueError):
            self.cipher.decrypt(b'invalid_length')
    
    def test_pkcs7_padding(self):
        """Test PKCS7 padding and unpadding."""
        data = b"Hello"
        padded = pkcs7_pad(data)
        
        self.assertEqual(len(padded), 16)
        self.assertEqual(padded[-11:], b'\x0b' * 11)
        
        unpadded = pkcs7_unpad(padded)
        self.assertEqual(unpadded, data)
    
    def test_text_bytes_conversion(self):
        """Test text to bytes and back conversion."""
        text = "Hello, AES!"
        
        as_bytes = text_to_bytes(text)
        back_to_text = bytes_to_text(as_bytes)
        
        self.assertEqual(text, back_to_text)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and special inputs."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cipher = AES128(b'0123456789abcdef')
    
    def test_single_character(self):
        """Test encryption of single character."""
        plaintext = "A"
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt_text(ciphertext)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_unicode_support(self):
        """Test encryption of Unicode characters."""
        plaintext = "Hëllö Wörld 你好 🎉"
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt_text(ciphertext)
        
        self.assertEqual(plaintext, decrypted)
    
    def test_16_byte_exact(self):
        """Test encryption of exactly 16 bytes."""
        plaintext = "1234567890123456"  # Exactly 16 bytes
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt_text(ciphertext)
        
        self.assertEqual(plaintext, decrypted)
        # Should have 32 bytes (16 original + 16 bytes of padding)
        self.assertEqual(len(ciphertext), 32)


def run_tests():
    """Run all tests."""
    unittest.main(argv=[''], exit=False, verbosity=2)


if __name__ == "__main__":
    run_tests()
