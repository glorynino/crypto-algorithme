"""Utility functions for data formatting and transformation."""


def text_to_bytes(text):
    """Convert text string to bytes using UTF-8 encoding."""
    return text.encode('utf-8')


def bytes_to_text(byte_data):
    """Convert bytes to text string using UTF-8 encoding."""
    return byte_data.decode('utf-8')


def pkcs7_pad(data, block_size=16):
    """Apply PKCS#7 padding to data."""
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)


def pkcs7_unpad(data):
    """Remove PKCS#7 padding from data."""
    padding_length = data[-1]
    
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid PKCS#7 padding.")
    
    return data[:-padding_length]


def split_blocks(data, block_size=16):
    """Split data into blocks of specified size."""
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]


def create_aes_blocks(text):
    """Prepare text/bytes into padded AES blocks."""
    if isinstance(text, str):
        return split_blocks(pkcs7_pad(text_to_bytes(text)))
    elif isinstance(text, bytes):
        return split_blocks(pkcs7_pad(text))
    else:
        raise TypeError("Input must be a string or bytes.")


def create_state_matrix(block):
    """Convert 16-byte block into 4x4 state matrix (column-major order)."""
    if len(block) != 16:
        raise ValueError("Block size must be 16 bytes.")
    
    state = [[0] * 4 for _ in range(4)]
    
    for i in range(16):
        row = i % 4
        col = i // 4
        state[row][col] = block[i]
    
    return state


def state_to_bytes(state):
    """Convert 4x4 state matrix back to 16 bytes (column-major order)."""
    if len(state) != 4 or any(len(row) != 4 for row in state):
        raise ValueError("State must be a 4x4 matrix.")
    
    return bytes(state[row][col] for col in range(4) for row in range(4))