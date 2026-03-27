MOD_VALUE = 26 # size of the alphabets

def letter_to_index(letter):
    if not letter.isalpha():
        raise ValueError(f"{letter} is not a letter!")
    return ord(letter.upper()) - ord('A') 

def index_to_letter(index, is_upper):
    letter = chr(ord('A') + index)
    return letter if is_upper else letter.lower()

def caesar_cipher(text, shift):
    ciphered_text = ""
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            index = letter_to_index(char)
            shifted_index = (index + shift) % MOD_VALUE
            ciphered_char = index_to_letter(shifted_index, is_upper)
            ciphered_text += ciphered_char
        else:
            ciphered_text += char
    return ciphered_text

def caesar_decipher(text, shift):
    return caesar_cipher(text, -shift)