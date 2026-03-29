import math

def chiffrement_affine(plain_text, a, b):
    cipher_text = ""
    for char in plain_text:
        # hna isalpha elle verifie si le caractere rentre est une lettre ou pas car je n'ai pas pris en consideration les num et ...
        if char.isalpha(): 
            # ord c pour avoir le code ASCII et bien sur le numero des lettre et entre 0 et 25
            x = ord(char.upper()) - ord('A')
            y = (a * x + b) % 26
            # rendre le chiffre reslutant en code ascii
            cipher_char = chr(y + ord('A'))
            cipher_text += cipher_char
        else:
            cipher_text += char
    return cipher_text

def déchiffrement_affine(cipher_text, a, b):
    plain_text = ""
    a_inv = pow(a, -1, 26)  # Calcul de l'inverse multiplicatif de a modulo 26
    for char in cipher_text:
        if char.isalpha():
            y = ord(char.upper()) - ord('A')
            x = (a_inv * (y - b)) % 26
            plain_char = chr(x + ord('A'))
            plain_text += plain_char
        else:
            plain_text += char
    return plain_text

def __main__():
    print("===================================== Méthode de chiffrement Affine ================================")
    while True:
        print("\033[32m 1. Taper 1 si vous voulez chiffrer un texte \033[32m")
        print("\033[34m 2. Taper 2 si vous voulez déchiffrer un texte \033[34m")
        print("\033[33m 2. Taper q si vous voulez quittez \033[33m")
        choix = input("\033[37m Entrez votre choix:\033[37m")
        if(choix == '1'):
            input_text = input("=> Entrez le texte à chiffrer:")
            
            a = int(input("===> Entrez la valeur de a (doit être premier avec 26 exemple : 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25, 27, 29): "))
            if (math.gcd(a, 26) != 1):
                print("!! La valeur de a doit être premier avec 26. Veuillez réessayer !!")
                while (math.gcd(a, 26) != 1):
                    a = int(input("===> Re-entrez la valeur de a (doit être premier avec 26):"))

            b = int(input("===> Entrez la valeur de b (doit être entre 0 et 25): "))
            texte_chiffré = chiffrement_affine(input_text,a ,b)
            print("Le texte chiffré est: ", texte_chiffré)
        elif(choix == '2'):
            a = int(input("===> Entrez la valeur de a utilisée pour le chiffrement (doit être premier avec 26): "))
            if (math.gcd(a, 26) != 1):
                print("!! La valeur de a doit être premier avec 26. Veuillez réessayer !!")
                while (math.gcd(a, 26) != 1):
                    a = int(input("===> Re-entrez la valeur de a (doit être premier avec 26):"))
            b = int(input("===> Entrez la valeur de b utilisée pour le chiffrement (doit être entre 0 et 25): "))
            input_text = input("=> Entrez le texte à déchiffrer: ")
            texte_déchiffré = déchiffrement_affine(input_text, a, b)
            print("Le texte déchiffré est: ", texte_déchiffré)
        elif(choix == 'q'):
            print("Merci d'avoir utilisé notre programme de chiffrement Affine. Au revoir!")
            break
        else:
            print("!! Choix invalide. Veuillez réessayer !!")



__main__()