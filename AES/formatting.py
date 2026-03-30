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

def text_to_aes_blocks(text):
    return split_blocks(pkcs7_pad(text_to_bytes(text)))