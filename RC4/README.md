# RC4 — Algorithme de chiffrement par flot

Implémentation de l'algorithme RC4 (Rivest Cipher 4) en Python, avec chiffrement et déchiffrement symétrique.

---

## Description

RC4 est un algorithme de chiffrement par flot qui génère un keystream pseudo-aléatoire à partir d'une clé secrète. Ce keystream est ensuite combiné avec le message via une opération XOR pour produire le message chiffré.

Comme RC4 est **symétrique**, la même opération (et la même clé) permet à la fois de chiffrer et de déchiffrer.

---

## Structure du projet

```
RC4/
├── rc4.py       # Implémentation de l'algorithme
├── tests.py     # Tests fonctionnels
└── README.md
```

---

## Fonctionnement

RC4 repose sur deux étapes :

**1. KSA — Key Scheduling Algorithm**
Initialise et mélange un tableau de 256 valeurs en fonction de la clé fournie.

**2. PRGA — Pseudo-Random Generation Algorithm**
Génère le keystream octet par octet, puis applique un XOR avec chaque caractère du message.

---

## Utilisation

### Lancer le programme

```bash
python rc4.py
```

Le programme demande une clé et un message, puis affiche le résultat chiffré.

### Utiliser les fonctions directement

```python
from rc4 import encryption, decryption

key = "ma_cle_secrete"
message = "bonjour"

encrypted = encryption(key, message)   # retourne une liste d'entiers
decrypted = decryption(key, encrypted) # retourne le message original

print(decrypted)  # bonjour
```

---

## Tests

```bash
python tests.py
```

Les tests vérifient que :
- le chiffrement suivi du déchiffrement restitue le message original
- une mauvaise clé ne déchiffre pas correctement
- deux clés différentes produisent deux chiffrés différents
- un message vide est géré sans erreur
- une clé d'un seul caractère fonctionne correctement

---

## Limites et avertissements

> **RC4 n'est plus considéré comme sécurisé** pour un usage en production.
> Des vulnérabilités ont été découvertes dans son keystream, notamment des biais statistiques dans les premiers octets générés.
> Il est déconseillé pour tout système nécessitant une sécurité réelle (TLS, Wi-Fi, etc.).

Ce projet est réalisé à des fins **pédagogiques** pour comprendre le fonctionnement des chiffrements par flot.

---

## Prérequis

- Python 3.x
- Aucune bibliothèque externe requise