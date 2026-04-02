
#playfair algorithm





def build_matrix(key):
    key = key.lower().replace('j', 'i')
    alphabet = "abcdefghiklmnopqrstuvwxyz"  # sans j (sois en fusionne le i et le j soit en enleve le Q pour avoir 25 caractere et pas 26 pour une matrice 5x5)

    ligne = []
    matrice = []
    j = 0

    # enlever doublons de la clé
    seen = ""
    for char in key:
        if char not in seen and char in alphabet:
            seen += char

    # enlever lettres de la clé de l'alphabet
    alphabet2 = ""
    for char in alphabet:
        if char not in seen:
            alphabet2 += char

    # concaténer clé + reste alphabet
    full = seen + alphabet2

    # construire matrice 5x5
    for char in full:
        ligne.append(char)
        j += 1

        if j == 5:
            matrice.append(ligne)
            ligne = []
            j = 0
     
    return matrice

def find_position(matrice, char):
    for i in range(5):
        for j in range(5):
            if matrice[i][j] == char:
                return i, j
   
def prepare_message(message):
    message = message.lower().replace('j', 'i')
    message = message.replace(" ", "") #enlever l'espace
    result = ""
    i = 0

    while i < len(message):
        a = message[i]

        if i + 1 < len(message):
            b = message[i + 1]

            if a == b:
                result += a + 'x'
                i += 1
            else:
                result += a + b
                i += 2
        else:
            result += a + 'x'
            i += 1

    return result
   
def encryption(message, matrice):
    resultat = []

    message = prepare_message(message)

    for i in range(0, len(message), 2):
        x = message[i]
        y = message[i+1]

        i1, j1 = find_position(matrice, x)
        i2, j2 = find_position(matrice, y)

        # même ligne
        if i1 == i2:
            resultat.append(matrice[i1][(j1+1)%5])
            resultat.append(matrice[i2][(j2+1)%5])

        # même colonne
        elif j1 == j2:
            resultat.append(matrice[(i1+1)%5][j1])
            resultat.append(matrice[(i2+1)%5][j2])

        # rectangle
        else:
            resultat.append(matrice[i1][j2])
            resultat.append(matrice[i2][j1])

    return "".join(resultat)

def decrypt(cipher, matrice):
    resultat = []

    for i in range(0, len(cipher), 2):
        x = cipher[i]
        y = cipher[i+1]

        i1, j1 = find_position(matrice, x)
        i2, j2 = find_position(matrice, y)

        # même ligne → gauche
        if i1 == i2:
            resultat.append(matrice[i1][(j1-1)%5])
            resultat.append(matrice[i2][(j2-1)%5])

        # même colonne → haut
        elif j1 == j2:
            resultat.append(matrice[(i1-1)%5][j1])
            resultat.append(matrice[(i2-1)%5][j2])

        # rectangle → pareil
        else:
            resultat.append(matrice[i1][j2])
            resultat.append(matrice[i2][j1])

    return "".join(resultat)


if __name__ == "__main__":
    key = "playfair"
    matrice = build_matrix(key)
    print("Matrice:")
    for row in matrice:
        print(row)

    message = "helloworld"
    print("\nMessage: ", message)
    cipher = encryption(message, matrice)
    print("Encrypted: ", cipher)
    decrypted_message = decrypt(cipher, matrice)
    print("Decrypted: ", decrypted_message)