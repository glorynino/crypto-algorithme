# RC4 algorithme

def encryption(key, message):
    # Initialisation du tableau S
    s = [i for i in range(256)]
    key_bytes = [ord(c) for c in key]

    # KSA — mélange du tableau en fonction de la clé
    j = 0
    for i in range(256):
        j = (j + s[i] + key_bytes[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]

    # PRGA — génération du keystream et XOR avec le message
    i = 0
    j = 0
    resultat = []
    for c in message:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) % 256
        k = s[t]
        resultat.append(ord(c) ^ k)

    
    return resultat  


def decryption(key, encrypted_message):
    # RC4 est symétrique : même opération pour déchiffrer
    s = [i for i in range(256)]
    key_bytes = [ord(c) for c in key]

    # KSA
    j = 0
    for i in range(256):
        j = (j + s[i] + key_bytes[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]

    # PRGA
    i = 0
    j = 0
    resultat = []
    for c in encrypted_message:  # c est un entier ici
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        t = (s[i] + s[j]) % 256
        k = s[t]
        resultat.append(c ^ k)

    resultat_chr = "".join(chr(x) for x in resultat)
    print("Message déchiffré :", resultat_chr)
    return resultat_chr


if __name__ == "__main__":
    key = input("Veuillez entrer la clé de chiffrement : ")
    message = input("Veuillez entrer le message à chiffrer : ")
    
    encrypted_message = encryption(key, message)   # retourne une liste d'entiers
    decryption(key, encrypted_message)             # déchiffre correctement