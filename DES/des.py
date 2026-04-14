import math

# ==========================================
# TABLES DE PERMUTATION DES
# ==========================================

# Permutation initiale (IP)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Permutation finale (IP^-1)
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
]

# Expansion E (32 bits -> 48 bits)
E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
]

# Permutation P (dans la fonction f)
P = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
]

# Permutation PC-1 (clé 64 bits -> 56 bits)
PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
]

# Permutation PC-2 (56 bits -> 48 bits)
PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Décalages pour la génération des sous-clés
DECALAGES = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-Boxes (8 boîtes de substitution)
S_BOXES = [
    # S1
    [
        [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
        [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
        [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
        [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]
    ],
    # S2
    [
        [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
        [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
        [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
        [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]
    ],
    # S3
    [
        [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
        [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
        [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
        [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]
    ],
    # S4
    [
        [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
        [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
        [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
        [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]
    ],
    # S5
    [
        [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
        [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
        [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
        [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]
    ],
    # S6
    [
        [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
        [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
        [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
        [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]
    ],
    # S7
    [
        [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
        [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
        [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
        [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]
    ],
    # S8
    [
        [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
        [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
        [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
        [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]
    ]
]


# ==========================================
# FONCTIONS UTILITAIRES
# ==========================================

def texte_vers_bits(texte):
    """Convertit une chaîne de caractères en liste de bits."""
    resultat = []
    for c in texte:
        bits = bin(ord(c))[2:].zfill(8)
        resultat.extend([int(b) for b in bits])
    return resultat

def bits_vers_texte(bits):
    """Convertit une liste de bits en chaîne de caractères."""
    chars = []
    for i in range(0, len(bits), 8):
        octet = bits[i:i+8]
        valeur = int(''.join(str(b) for b in octet), 2)
        chars.append(chr(valeur))
    return ''.join(chars)

def bits_vers_hex(bits):
    """Convertit une liste de bits en chaîne hexadécimale."""
    hex_str = ''
    for i in range(0, len(bits), 4):
        nibble = bits[i:i+4]
        hex_str += hex(int(''.join(str(b) for b in nibble), 2))[2:]
    return hex_str.upper()

def hex_vers_bits(hex_str, longueur=64):
    """Convertit une chaîne hexadécimale en liste de bits."""
    bits = bin(int(hex_str, 16))[2:].zfill(longueur)
    return [int(b) for b in bits]

def permuter(bloc, table):
    """Applique une permutation sur un bloc de bits selon une table."""
    return [bloc[table[i] - 1] for i in range(len(table))]

def xor(bits1, bits2):
    """XOR entre deux listes de bits."""
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def decalage_gauche(bits, n):
    """Décalage circulaire à gauche de n positions."""
    return bits[n:] + bits[:n]


# ==========================================
# GÉNÉRATION DES SOUS-CLÉS
# ==========================================

def generer_sous_cles(cle_bits):
    """
    Génère les 16 sous-clés de 48 bits à partir d'une clé de 64 bits.
    """
    # Appliquer PC-1 : 64 bits -> 56 bits
    cle_56 = permuter(cle_bits, PC1)

    # Diviser en deux moitiés C et D de 28 bits
    C = cle_56[:28]
    D = cle_56[28:]

    sous_cles = []

    for i in range(16):
        # Décalage circulaire à gauche
        C = decalage_gauche(C, DECALAGES[i])
        D = decalage_gauche(D, DECALAGES[i])

        # Combiner C et D, puis appliquer PC-2 : 56 bits -> 48 bits
        CD = C + D
        sous_cle = permuter(CD, PC2)
        sous_cles.append(sous_cle)

    return sous_cles


# ==========================================
# FONCTION f (Feistel)
# ==========================================

def s_box(bloc_6bits, numero_sbox):
    """
    Applique une S-Box sur un bloc de 6 bits.
    Retourne 4 bits.
    """
    # La ligne est déterminée par le 1er et le 6ème bit
    ligne = (bloc_6bits[0] << 1) | bloc_6bits[5]
    # La colonne est déterminée par les 4 bits du milieu
    colonne = (bloc_6bits[1] << 3) | (bloc_6bits[2] << 2) | (bloc_6bits[3] << 1) | bloc_6bits[4]

    valeur = S_BOXES[numero_sbox][ligne][colonne]
    return [int(b) for b in bin(valeur)[2:].zfill(4)]

def fonction_f(R, sous_cle):
    """
    Fonction de Feistel f(R, K) :
    1. Expansion E : 32 bits -> 48 bits
    2. XOR avec la sous-clé
    3. Substitution par S-Boxes : 48 bits -> 32 bits
    4. Permutation P
    """
    # Étape 1 : Expansion
    R_etendu = permuter(R, E)  # 48 bits

    # Étape 2 : XOR avec la sous-clé
    R_xor = xor(R_etendu, sous_cle)  # 48 bits

    # Étape 3 : Substitution via S-Boxes
    sortie_s = []
    for i in range(8):
        bloc = R_xor[i*6:(i+1)*6]  # Blocs de 6 bits
        sortie_s.extend(s_box(bloc, i))  # 4 bits par S-Box -> 32 bits total

    # Étape 4 : Permutation P
    resultat = permuter(sortie_s, P)

    return resultat


# ==========================================
# CHIFFREMENT / DÉCHIFFREMENT D'UN BLOC
# ==========================================

def des_bloc(bloc_bits, sous_cles):
    """
    Chiffre ou déchiffre un bloc de 64 bits avec DES.
    - Pour chiffrer : passer les sous-clés dans l'ordre normal
    - Pour déchiffrer : passer les sous-clés en ordre inverse
    """
    # Permutation initiale
    bloc = permuter(bloc_bits, IP)

    # Diviser en L et R de 32 bits
    L = bloc[:32]
    R = bloc[32:]

    # 16 tours de Feistel
    for i in range(16):
        L_nouveau = R
        R_nouveau = xor(L, fonction_f(R, sous_cles[i]))
        L = L_nouveau
        R = R_nouveau

    # Recombinaison R16 + L16 (inversion finale)
    RL = R + L

    # Permutation finale IP^-1
    bloc_chiffre = permuter(RL, IP_INV)

    return bloc_chiffre


# ==========================================
# CHIFFREMENT DES - MODE ECB
# ==========================================

def chiffrement_des(texte_clair, cle_hex):
    """
    Chiffre un texte en utilisant DES en mode ECB.
    
    Paramètres:
        texte_clair : str  - Le message à chiffrer
        cle_hex     : str  - Clé de 16 caractères hexadécimaux (64 bits)
    
    Retourne:
        str - Le texte chiffré en hexadécimal
    """
    # Convertir la clé hex en bits
    cle_bits = hex_vers_bits(cle_hex, 64)

    # Générer les 16 sous-clés
    sous_cles = generer_sous_cles(cle_bits)

    # Convertir le texte en bits
    bits_texte = texte_vers_bits(texte_clair)

    # Padding PKCS#5 pour compléter à un multiple de 64 bits
    nb_octets_padding = 8 - (len(texte_clair) % 8)
    bits_texte.extend(texte_vers_bits(chr(nb_octets_padding) * nb_octets_padding))

    # Chiffrer bloc par bloc (64 bits = 8 octets)
    bits_chiffres = []
    for i in range(0, len(bits_texte), 64):
        bloc = bits_texte[i:i+64]
        bloc_chiffre = des_bloc(bloc, sous_cles)
        bits_chiffres.extend(bloc_chiffre)

    return bits_vers_hex(bits_chiffres)


# ==========================================
# DÉCHIFFREMENT DES - MODE ECB
# ==========================================

def dechiffrement_des(texte_chiffre_hex, cle_hex):
    """
    Déchiffre un texte chiffré avec DES en mode ECB.
    
    Paramètres:
        texte_chiffre_hex : str - Le texte chiffré en hexadécimal
        cle_hex           : str - Clé de 16 caractères hexadécimaux (64 bits)
    
    Retourne:
        str - Le texte déchiffré
    """
    # Convertir la clé hex en bits
    cle_bits = hex_vers_bits(cle_hex, 64)

    # Générer les 16 sous-clés (inversées pour le déchiffrement)
    sous_cles = generer_sous_cles(cle_bits)
    sous_cles_inv = sous_cles[::-1]

    # Convertir le texte chiffré hex en bits
    bits_chiffres = hex_vers_bits(texte_chiffre_hex, len(texte_chiffre_hex) * 4)

    # Déchiffrer bloc par bloc
    bits_clairs = []
    for i in range(0, len(bits_chiffres), 64):
        bloc = bits_chiffres[i:i+64]
        bloc_clair = des_bloc(bloc, sous_cles_inv)
        bits_clairs.extend(bloc_clair)

    # Retirer le padding PKCS#5
    texte = bits_vers_texte(bits_clairs)
    nb_padding = ord(texte[-1])
    return texte[:-nb_padding]


# ==========================================
# CHIFFREMENT CBC (bonus - comme dans votre code original)
# ==========================================

def chiffrement_cbc(texte_clair, cle_hex, iv_hex):
    """
    Chiffre un texte en utilisant DES en mode CBC.
    
    Paramètres:
        texte_clair : str - Le message à chiffrer
        cle_hex     : str - Clé hexadécimale (64 bits)
        iv_hex      : str - Vecteur d'initialisation hexadécimal (64 bits)
    
    Retourne:
        str - Le texte chiffré en hexadécimal
    """
    cle_bits = hex_vers_bits(cle_hex, 64)
    sous_cles = generer_sous_cles(cle_bits)
    vecteur = hex_vers_bits(iv_hex, 64)

    bits_texte = texte_vers_bits(texte_clair)

    # Padding PKCS#5
    nb_octets_padding = 8 - (len(texte_clair) % 8)
    bits_texte.extend(texte_vers_bits(chr(nb_octets_padding) * nb_octets_padding))

    bits_chiffres = []
    for i in range(0, len(bits_texte), 64):
        bloc = bits_texte[i:i+64]
        # CBC : XOR avec le bloc précédent (ou IV pour le 1er bloc)
        bloc_xor = xor(bloc, vecteur)
        bloc_chiffre = des_bloc(bloc_xor, sous_cles)
        bits_chiffres.extend(bloc_chiffre)
        vecteur = bloc_chiffre  # Le bloc chiffré devient le nouveau vecteur

    return bits_vers_hex(bits_chiffres)


def dechiffrement_cbc(texte_chiffre_hex, cle_hex, iv_hex):
    """
    Déchiffre un texte chiffré avec DES en mode CBC.
    """
    cle_bits = hex_vers_bits(cle_hex, 64)
    sous_cles = generer_sous_cles(cle_bits)[::-1]
    vecteur = hex_vers_bits(iv_hex, 64)

    bits_chiffres = hex_vers_bits(texte_chiffre_hex, len(texte_chiffre_hex) * 4)

    bits_clairs = []
    for i in range(0, len(bits_chiffres), 64):
        bloc = bits_chiffres[i:i+64]
        bloc_dechiffre = des_bloc(bloc, sous_cles)
        bloc_clair = xor(bloc_dechiffre, vecteur)
        bits_clairs.extend(bloc_clair)
        vecteur = bloc  # Le bloc chiffré devient le nouveau vecteur

    texte = bits_vers_texte(bits_clairs)
    nb_padding = ord(texte[-1])
    return texte[:-nb_padding]


# ==========================================
# PROGRAMME PRINCIPAL
# ==========================================

def __main__():
    print("=" * 50)
    print("   ALGORITHME DE CHIFFREMENT DES")
    print("=" * 50)

    # Clé de test (64 bits = 16 caractères hex)
    cle = "133457799BBCDFF1"
    # Vecteur d'initialisation pour CBC
    iv  = "0000000000000000"

    message = "Bonjour!"

    print(f"\nMessage original  : {message}")
    print(f"Clé (hex)         : {cle}")

    # --- Mode ECB ---
    print("\n--- Mode ECB ---")
    chiffre_ecb = chiffrement_des(message, cle)
    print(f"Texte chiffré     : {chiffre_ecb}")
    dechiffre_ecb = dechiffrement_des(chiffre_ecb, cle)
    print(f"Texte déchiffré   : {dechiffre_ecb}")

    # --- Mode CBC ---
    print("\n--- Mode CBC ---")
    print(f"IV (hex)          : {iv}")
    chiffre_cbc = chiffrement_cbc(message, cle, iv)
    print(f"Texte chiffré     : {chiffre_cbc}")
    dechiffre_cbc = dechiffrement_cbc(chiffre_cbc, cle, iv)
    print(f"Texte déchiffré   : {dechiffre_cbc}")

    print("\n" + "=" * 50)
    print("Vérification : ", "✓ SUCCÈS" if dechiffre_ecb == message else "✗ ÉCHEC")

__main__()