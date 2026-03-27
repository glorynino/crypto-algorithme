MOD_VALUE = 26 # size of the alphabets

def letter_to_index(letter):
    if not letter.isalpha():
        raise ValueError(f"{letter} is not a letter!")
    return ord(letter.upper()) - ord('A') 

def index_to_letter(index, is_upper):
    letter = chr(ord('A') + index)
    return letter if is_upper else letter.lower()

def encrypt_vignere(text, key):
    encrypted_text = ""
    formatted_key = ""
    key_len = len(key)
    key_index = 0
    
    for char in text:
        if char.isalpha():
            formatted_key += key[key_index % key_len]
            key_index += 1
    key_index = 0
    
    for char in text:
        if char.isalpha():
            encrypted_text += index_to_letter(
                (letter_to_index(char) + letter_to_index(formatted_key[key_index])) % MOD_VALUE,
                char.isupper()
            )
            key_index += 1
        else:
            encrypted_text += char
            
    return encrypted_text

def decrypt_vignere(encrypted_text, key):
    decrypted_text = ""
    formatted_key = ""
    key_len = len(key)
    key_index = 0
    
    for char in encrypted_text:
        if char.isalpha():
            formatted_key += key[key_index % key_len]
            key_index += 1
    key_index = 0
    
    for char in encrypted_text:
        if char.isalpha():
            decrypted_text += index_to_letter(
                (letter_to_index(char) - letter_to_index(formatted_key[key_index]) + MOD_VALUE) % MOD_VALUE,
                char.isupper() 
            )
            key_index += 1
        else:
            decrypted_text += char
            
    return decrypted_text