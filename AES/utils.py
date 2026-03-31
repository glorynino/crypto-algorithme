def text_to_bytes(text):
    return text.encode('utf-8')

def bytes_to_text(byte_data):
    return byte_data.decode('utf-8')

def pkcs7_pad(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)

def pkcs7_unpad(data):
    padding_length = data[-1]
    
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid PKCS#7 padding.")
    
    return data[:-padding_length]

def split_blocks(data, block_size=16):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def create_aes_blocks(text):
    if isinstance(text, str):
        return split_blocks(pkcs7_pad(text_to_bytes(text)))
    elif isinstance(text, bytes):
        return split_blocks(pkcs7_pad(text))
    else:
        raise TypeError("Input must be a string or bytes.")

def create_state_matrix(block):
    if(len(block) != 16):
        raise ValueError("Block size must be 16 bytes.")
    
    state = [[0] * 4 for _ in range(4)]
    
    for i in range (16):
        row = i % 4
        col = i // 4
        state[row][col] = block[i]
        
    return state

def state_to_bytes(state):
    if len(state) != 4 or any(len(row) != 4 for row in state):
        raise ValueError("State must be a 4x4 matrix.")
    
    return bytes(state[row][col] for col in range(4) for row in range(4))