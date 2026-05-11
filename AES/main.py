"""AES-128 Cipher - Main Entry Point."""

from cipher import AES128
import binascii


def main():
    """CLI interface for AES-128 encryption/decryption."""
    print("=" * 50)
    print("AES-128 Cipher")
    print("=" * 50)
    
    while True:
        print("\nOptions:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        
        choice = input("\nSelect option (1-3): ").strip()
        
        if choice == '1':
            encrypt_message()
        elif choice == '2':
            decrypt_message()
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")


def encrypt_message():
    """Encrypt a message using AES-128."""
    try:
        # Get key
        key_input = input("Enter 16-character key: ").strip()
        if len(key_input) != 16:
            print(f"Error: Key must be exactly 16 characters. You provided {len(key_input)}.")
            return
        
        key = key_input.encode('utf-8')
        
        # Get plaintext
        plaintext = input("Enter plaintext to encrypt: ").strip()
        if not plaintext:
            print("Error: Plaintext cannot be empty.")
            return
        
        # Encrypt
        cipher = AES128(key)
        ciphertext = cipher.encrypt(plaintext)
        
        # Display results
        print("\n" + "-" * 50)
        print(f"Plaintext: {plaintext}")
        print(f"Hex Ciphertext: {binascii.hexlify(ciphertext).decode()}")
        print("-" * 50)
        
    except Exception as e:
        print(f"Encryption error: {e}")


def decrypt_message():
    """Decrypt a message using AES-128."""
    try:
        # Get key
        key_input = input("Enter 16-character key: ").strip()
        if len(key_input) != 16:
            print(f"Error: Key must be exactly 16 characters. You provided {len(key_input)}.")
            return
        
        key = key_input.encode('utf-8')
        
        # Get ciphertext (hex format)
        ciphertext_hex = input("Enter hex ciphertext to decrypt: ").strip()
        try:
            ciphertext = binascii.unhexlify(ciphertext_hex)
        except Exception:
            print("Error: Invalid hex format.")
            return
        
        # Decrypt
        cipher = AES128(key)
        plaintext = cipher.decrypt_text(ciphertext)
        
        # Display results
        print("\n" + "-" * 50)
        print(f"Hex Ciphertext: {ciphertext_hex}")
        print(f"Plaintext: {plaintext}")
        print("-" * 50)
        
    except Exception as e:
        print(f"Decryption error: {e}")


if __name__ == "__main__":
    main()
