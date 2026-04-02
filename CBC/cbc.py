import math
import random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES

# fonction de chiffrement cbc
def chiffrement_cbc(texte_clair, clé):
    # Générer un vecteur d'initialisation (IV) aléatoire
    iv = get_random_bytes(8)  # 8 bytes pour DES
    # Initialiser le texte chiffré avec l'IV
    texte_chiffré = iv
    # Appliquer le padding PKCS#5/PKCS#7
    texte_clair_bytes = texte_clair.encode()
    padding_len = 8 - (len(texte_clair_bytes) % 8)
    if padding_len == 0:
        padding_len = 8
    texte_clair_bytes += bytes([padding_len] * padding_len)
    # Diviser le texte clair en blocs de 8 bytes
    for i in range(0, len(texte_clair_bytes), 8):
        bloc_clair = texte_clair_bytes[i:i+8]
        # XOR du bloc clair avec le bloc chiffré précédent (ou IV pour le premier bloc)
        bloc_xor = bytes(a ^ b for a, b in zip(bloc_clair, texte_chiffré[-8:]))
        # Chiffrer le bloc XORé avec la clé (utiliser une fonction de chiffrement symétrique comme DES ou AES)
        bloc_chiffré = chiffrement_symétrique(bloc_xor, clé)
        # Ajouter le bloc chiffré au texte chiffré
        texte_chiffré += bloc_chiffré
    return texte_chiffré.hex()

def chiffrement_symétrique(bloc, clé):
    # Utiliser le chiffrement DES pour chiffrer le bloc
    cipher = DES.new(clé, DES.MODE_ECB)
    return cipher.encrypt(bloc)

def dechiffrement_cbc(texte_chiffré, clé):
    # Extraire le vecteur d'initialisation (IV)
    iv = texte_chiffré[:8]
    # Initialiser le texte déchiffré (sans l'IV)
    texte_déchiffré = b""
    # Diviser le texte chiffré en blocs de 8 bytes
    for i in range(8, len(texte_chiffré), 8):
        bloc_chiffré = texte_chiffré[i:i+8]
        # Déchiffrer le bloc chiffré avec la clé
        bloc_déchiffré = déchiffrement_symétrique(bloc_chiffré, clé)
        # XOR du bloc déchiffré avec le bloc chiffré précédent (ou IV pour le premier bloc)
        bloc_xor = bytes(a ^ b for a, b in zip(bloc_déchiffré, texte_chiffré[i-8:i]))
        # Ajouter le bloc déchiffré au texte déchiffré
        texte_déchiffré += bloc_xor
    # Retirer le padding
    if texte_déchiffré:
        padding_len = texte_déchiffré[-1]
        texte_déchiffré = texte_déchiffré[:-padding_len]
    return texte_déchiffré.hex()

def déchiffrement_symétrique(bloc, clé):
    # Utiliser le chiffrement DES pour déchiffrer le bloc
    cipher = DES.new(clé, DES.MODE_ECB)
    return cipher.decrypt(bloc)

def __main__():
    print("===================================== Méthode de chiffrement CBC ================================")
    while True:
        print("\033[32m 1. Taper 1 si vous voulez chiffrer un texte \033[32m")
        print("\033[34m 2. Taper 2 si vous voulez déchiffrer un texte \033[34m")
        print("\033[33m 2. Taper q si vous voulez quittez \033[33m")
        choix = input("\033[37m Entrez votre choix:\033[37m")
        if(choix == '1'):
            input_text = input("=> Entrez le texte à chiffrer:")
            clé = get_random_bytes(8)  # Générer une clé aléatoire de 8 bytes pour DES
            print("Le texte chiffré est :", chiffrement_cbc(input_text, clé))
        elif(choix == '2'):
            clé = get_random_bytes(8)  # Générer une clé aléatoire de 8 bytes pour DES
            input_text = input("=> Entrez le texte à déchiffrer: ")
            print("Le texte déchiffré est :", dechiffrement_cbc(input_text, clé))
        elif(choix == 'q'):
            print("Merci d'avoir utilisé notre programme de chiffrement CBC. Au revoir!")
            break


__main__()