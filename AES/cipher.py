"""AES-128 Cipher Implementation."""

from constants import S_BOX, INV_S_BOX, R_CON
from utils import create_state_matrix, state_to_bytes, create_aes_blocks, pkcs7_unpad


class AES128:
    """AES-128 cipher implementation."""
    
    def __init__(self, key):
        """
        Initialize AES-128 cipher with a 16-byte key.
        
        Args:
            key: 16-byte encryption key (bytes)
        """
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes for AES-128.")
        self.key = key
        self.round_keys = self._expand_key(key)
    
    @staticmethod
    def _galois_mult(a, b):
        """Multiply two bytes in GF(2^8) (Galois Field)."""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            high_bit = a & 0x80
            a = (a << 1) & 0xff
            if high_bit:
                a ^= 0x1b
            b >>= 1
        return p
    
    @staticmethod
    def _sub_word(word):
        """Apply S-Box substitution to a 4-byte word."""
        return bytes(S_BOX[byte] for byte in word)
    
    @staticmethod
    def _rot_word(word):
        """Rotate a 4-byte word left by 1 byte."""
        return word[1:] + word[:1]
    
    def _expand_key(self, key):
        """Generate 11 round keys from the 16-byte master key."""
        # Split key into 4-byte words
        w = [key[i:i+4] for i in range(0, 16, 4)]
        
        for i in range(4, 44):
            temp = w[i - 1]
            
            if i % 4 == 0:
                temp = self._sub_word(self._rot_word(temp))
                temp = bytes(temp[j] ^ (R_CON[(i // 4) - 1] if j == 0 else 0) for j in range(4))
            
            w.append(bytes(w[i - 4][j] ^ temp[j] for j in range(4)))
        
        # Organize words into 11 round keys (16 bytes each)
        round_keys = [b''.join(w[i:i+4]) for i in range(0, 44, 4)]
        return round_keys
    
    @staticmethod
    def _sub_bytes(state):
        """Apply S-Box substitution to all bytes in state."""
        for row in range(4):
            for col in range(4):
                state[row][col] = S_BOX[state[row][col]]
        return state
    
    @staticmethod
    def _inv_sub_bytes(state):
        """Apply inverse S-Box substitution to all bytes in state."""
        for row in range(4):
            for col in range(4):
                state[row][col] = INV_S_BOX[state[row][col]]
        return state
    
    @staticmethod
    def _shift_rows(state):
        """Shift rows of state matrix."""
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        return state
    
    @staticmethod
    def _inv_shift_rows(state):
        """Inverse shift rows of state matrix."""
        state[1] = state[1][-1:] + state[1][:-1]
        state[2] = state[2][-2:] + state[2][:-2]
        state[3] = state[3][-3:] + state[3][:-3]
        return state
    
    @staticmethod
    def _mix_columns(state):
        """Mix columns of state matrix."""
        for col in range(4):
            s0, s1, s2, s3 = state[0][col], state[1][col], state[2][col], state[3][col]
            
            state[0][col] = AES128._galois_mult(s0, 2) ^ AES128._galois_mult(s1, 3) ^ s2 ^ s3
            state[1][col] = s0 ^ AES128._galois_mult(s1, 2) ^ AES128._galois_mult(s2, 3) ^ s3
            state[2][col] = s0 ^ s1 ^ AES128._galois_mult(s2, 2) ^ AES128._galois_mult(s3, 3)
            state[3][col] = AES128._galois_mult(s0, 3) ^ s1 ^ s2 ^ AES128._galois_mult(s3, 2)
        
        return state
    
    @staticmethod
    def _inv_mix_columns(state):
        """Inverse mix columns of state matrix."""
        for col in range(4):
            s0, s1, s2, s3 = state[0][col], state[1][col], state[2][col], state[3][col]
            
            state[0][col] = (AES128._galois_mult(s0, 0x0e) ^ AES128._galois_mult(s1, 0x0b) ^
                           AES128._galois_mult(s2, 0x0d) ^ AES128._galois_mult(s3, 0x09))
            state[1][col] = (AES128._galois_mult(s0, 0x09) ^ AES128._galois_mult(s1, 0x0e) ^
                           AES128._galois_mult(s2, 0x0b) ^ AES128._galois_mult(s3, 0x0d))
            state[2][col] = (AES128._galois_mult(s0, 0x0d) ^ AES128._galois_mult(s1, 0x09) ^
                           AES128._galois_mult(s2, 0x0e) ^ AES128._galois_mult(s3, 0x0b))
            state[3][col] = (AES128._galois_mult(s0, 0x0b) ^ AES128._galois_mult(s1, 0x0d) ^
                           AES128._galois_mult(s2, 0x09) ^ AES128._galois_mult(s3, 0x0e))
        
        return state
    
    @staticmethod
    def _add_round_key(state, round_key):
        """XOR state with round key."""
        for col in range(4):
            for row in range(4):
                state[row][col] ^= round_key[col * 4 + row]
        return state
    
    def _encrypt_block(self, plaintext_block):
        """Encrypt a single 16-byte block."""
        if len(plaintext_block) != 16:
            raise ValueError("Plaintext block must be 16 bytes.")
        
        state = create_state_matrix(plaintext_block)
        state = self._add_round_key(state, self.round_keys[0])
        
        for round_num in range(1, 10):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[round_num])
        
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[10])
        
        return state_to_bytes(state)
    
    def _decrypt_block(self, ciphertext_block):
        """Decrypt a single 16-byte block."""
        if len(ciphertext_block) != 16:
            raise ValueError("Ciphertext block must be 16 bytes.")
        
        state = create_state_matrix(ciphertext_block)
        state = self._add_round_key(state, self.round_keys[10])
        
        for round_num in range(9, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self.round_keys[round_num])
            state = self._inv_mix_columns(state)
        
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, self.round_keys[0])
        
        return state_to_bytes(state)
    
    def encrypt(self, plaintext):
        """Encrypt plaintext (string or bytes) with ECB mode."""
        blocks = create_aes_blocks(plaintext)
        ciphertext = b''
        for block in blocks:
            ciphertext += self._encrypt_block(block)
        return ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext (bytes) with ECB mode."""
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of 16 bytes.")
        
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            plaintext += self._decrypt_block(ciphertext[i:i+16])
        
        return pkcs7_unpad(plaintext)
    
    def decrypt_text(self, ciphertext):
        """Decrypt ciphertext and return as UTF-8 string."""
        plaintext_bytes = self.decrypt(ciphertext)
        return plaintext_bytes.decode('utf-8')
