# TP 1 - CHIFFREMENT CLASSIQUE

## Objectif
Implémenter et analyser les vulnérabilités des chiffreurs classiques :
- **César** : chiffre par substitution mono-alphabétique
- **Vigenère** : chiffre par substitution polyalphabétique
- **Hill** : chiffre par substitution linéaire/matricielle
- **OTP/Vernam** : chiffre par addition (théoriquement parfait)

---

## Structure du Projet

```
TP1/
├── Caesar cipher/
│   ├── caesar.py          # Implémentation de base
│   ├── caesar_attacks.py  # Attaques: force brute, IC, chi-squared
│   └── tests.py
│
├── Vignere cipher/
│   ├── vignere.py         # Implémentation de base
│   ├── vignere_attacks.py # Attaques: Kasiski, IC, récupération clé
│   └── tests.py
│
├── HILL/
│   ├── hill.py            # Implémentation 2x2 et 3x3
│   ├── hill_attacks.py    # Attaque à clair connu
│   └── tests.py
│
├── OTP algorithm/
│   ├── otp.py             # Implémentation basique
│   ├── otp_attacks.py     # Attaques: réutilisation clé, crib dragging
│   └── tests.py
│
├── tp1_complete.py        # Tests complets de tous les exercices
└── test_tp1_quick.py      # Quick test du Caesar
```

---

## Exercice 1.1 - Chiffre de César

### Implémentation de base
```python
from caesar import caesar_cipher, caesar_decipher

plaintext = "THEQUICKBROWNFOX"
shift = 3
ciphertext = caesar_cipher(plaintext, shift)  # "WKHTXLFNERZQIIR"
decrypted = caesar_decipher(ciphertext, shift)  # "THEQUICKBROWNFOX"
```

### Attaque 1: Force Brute (Dictionnaire)
```python
from caesar_attacks import brute_force_caesar

candidates = brute_force_caesar(ciphertext, top_n=5)
# Retourne les 5 meilleurs candidats avec scores de confiance
```

**Fonctionnement:**
- Teste les 26 shifts possibles
- Compte les mots reconnus français dans chaque déclinaison
- Retourne les candidats triés par confiance

### Attaque 2: Analyse de Fréquences (IC)
```python
from caesar_attacks import frequency_analysis_caesar

shift, plaintext, ic_value = frequency_analysis_caesar(ciphertext)
# IC française ≈ 0.074
# Chiffrement aléatoire: ≈ 0.038
```

**Concept:**
- L'Indice de Coïncidence (IC) mesure la similitude statistique du texte
- French: IC = Σ(ni*(ni-1)) / (N*(N-1)) ≈ 0.074
- On teste tous les shifts et cherche celui avec IC ≈ 0.074

### Attaque 3: Chi-Squared
```python
from caesar_attacks import chi_squared_attack_caesar

candidates = chi_squared_attack_caesar(ciphertext, top_n=3)
# Compare la distribution de fréquences observée vs théorique française
```

---

## Exercice 1.2 - Chiffre de Vigenère

### Implémentation de base
```python
from vignere import encrypt_vignere, decrypt_vignere

plaintext = "THEQUICKBROWNFOX"
key = "SECRET"
ciphertext = encrypt_vignere(plaintext, key)
decrypted = decrypt_vignere(ciphertext, key)
```

### Attaque 1: Test de Kasiski (Trigrammes répétés)
```python
from vignere_attacks import kasiski_test, estimate_key_length_kasiski

results = kasiski_test(ciphertext)
key_lengths = estimate_key_length_kasiski(ciphertext, top_n=5)
# Analyse les trigrammes répétés pour estimer la longueur de clé
```

**Principe:**
- Les trigrammes répétés dans le ciphertext indiquent une répétition de clé
- Distance entre répétitions = multiple de la longueur de clé
- Trouver le GCD des distances → longueur probable

### Attaque 2: Index de Coïncidence (IC)
```python
from vignere_attacks import index_of_coincidence_attack

ic_scores, (best_length, best_ic) = index_of_coincidence_attack(ciphertext)
# Pour chaque longueur possible k:
#   - Divise ciphertext en k sous-séquences
#   - Calcule IC moyen
#   - Si IC ≈ 0.074 → bonne longueur trouvée!
```

### Attaque 3: Récupération de la Clé
```python
from vignere_attacks import recover_key_from_ic

key_recovered = recover_key_from_ic(ciphertext, key_length=6)
# Pour chaque position de clé:
#   - Déchiffre avec tous les shifts possibles
#   - Calcule chi-squared vs français
#   - Retourne le shift avec meilleur match
```

---

## Exercice 1.3 - Chiffre de Hill

### Implémentation de base (2×2 et 3×3)
```python
from hill import encrypt_hill, decrypt_hill

plaintext = "HILLCIPHER"
key_2x2 = [[5, 8], [17, 3]]
ciphertext = encrypt_hill(plaintext, key_2x2)
decrypted = decrypt_hill(ciphertext, key_2x2)
```

**Concept:**
- Divise le texte en blocs (2 ou 3 caractères)
- Chaque bloc est traité comme un vecteur V
- Chiffrement: **C = K × V (mod 26)**
- Déchiffrement: **P = K⁻¹ × C (mod 26)**
- K doit être inversible mod 26: gcd(det(K), 26) = 1

### Attaque: Clair Connu (Known-Plaintext)
```python
from hill_attacks import known_plaintext_attack_hill

key_recovered = known_plaintext_attack_hill(plaintext, ciphertext, block_size=2)
# Résout: K = C × P⁻¹ (mod 26)
```

**Vulnérabilité:**
- Structure linéaire révèle tout avec peu de clair connu
- 2 blocs clair-chiffré suffisent pour retrouver une clé 2×2
- 3 blocs clair-chiffré suffisent pour retrouver une clé 3×3

---

## Exercice 1.4 - One-Time Pad (Vernam)

### Implémentation de base
```python
from otp import encryption, decryption

message = "HELLO WORLD"
ciphertext, key = encryption(message)
# key = clé aléatoire (même longueur que message)
# ciphertext = message ⊕ key (XOR octet-par-octet)

decrypted = decryption(ciphertext, key)
```

### Attaque 1: Réutilisation de Clé
```python
from otp_attacks import otp_key_reuse_attack

result = otp_key_reuse_attack(m1, m2)
# Si même clé K utilisée:
#   C1 = M1 ⊕ K
#   C2 = M2 ⊕ K
#   C1 ⊕ C2 = M1 ⊕ M2  ← clé s'annule!
```

**Danger:**
- Une seule réutilisation casse la sécurité
- L'attaquant n'a pas K directement, mais M1 ⊕ M2
- C1 ⊕ C2 révèle les structure et redondance des deux textes

### Attaque 2: Crib Dragging
```python
from otp_attacks import crib_dragging_attack

crib_results = crib_dragging_attack(c1, c2, known_plaintext_crib="THE")
# Si attaquant soupçonne "THE" dans M1:
#   Pour chaque position:
#     - Calcule ce que M2 devrait être: M2 = "THE" ⊕ (C1 ⊕ C2)
#     - Si M2 ressemble à du texte valide → position correcte trouvée!
```

---

## Sécurité et Vulnérabilités

| Chiffre | Vulnérabilité Principale | Attaque | Complexité |
|---------|----------------------|---------|-----------|
| **César** | Petit espace de clé | Force brute | O(26) |
| ^| Distribution fréquence biaisée | IC/Chi-squared | O(26 × n) |
| **Vigenère** | Clé se répète | Kasiski + IC | O(k²×n) |
| ^| Chaque position = César indépendant | Analyse par décalage | O(26×k×n) |
| **Hill** | Structure linéaire | Clair connu / Matrice inverse | O(k³) |
| ^| Pas diffusion temporelle | Inversion modulo 26 | varie |
| **OTP** | Réutilisation de clé | Crib dragging | O(k×c) |
| ^| Gestion clés impratique | Stat. lang. sur XOR | heuristique |

---

## Exécution des Tests

### Test rapide (Caesar)
```bash
cd /home/matt-anis/Studies/Crypto
.venv/bin/python3 test_tp1_quick.py
```

### Tests complets (tous les exercices)
```bash
.venv/bin/python3 tp1_complete.py
```

### Tests individuels par module
```bash
cd "Caesar cipher"
.venv/bin/python3 tests.py

cd ../Vignere\ cipher
.venv/bin/python3 tests.py

cd ../HILL
.venv/bin/python3 tests.py  # Note: requiert sympy
```

---

## Points Clés d'Apprentissage

### 1. César
✓ Les substitutions simples ne résistent pas à la fréquence  
✓ L'IC révèle la langue même chiffrée  
✓ Force brute sur 26 clés triviale

### 2. Vigenère  
✓ Apparence plus sûre mais totalement cassable  
✓ Trigrammes répétés → longueur de clé trouvée  
✓ Puis chaque position = ataque César

### 3. Hill  
✓ Mathématiques ≠ Sécurité cryptographique  
✓ Linéarité expose tout en clair connu  
✓ Même matrices grandes restent linéaires

### 4. OTP  
✓ Théoriquement parfait mais **jamais réutiliser la clé**  
✓ Un seul message + réutilisation = compromission totale  
✓ Gestion pratique des clés = obstacle principal

---

## Quelques Questions de Réflexion

1. **César**: Pourquoi l'IC fonctionne-t-elle mieux que la fréquence simple?
2. **Vigenère**: Comment la longueur de clé affecte-t-elle la sécurité? (|K| = |M|?)
3. **Hill**: Pourquoi Hill(256) reste-t-il cassable en clair connu?
4. **OTP**: Quels obstacles pratiques empêchent le déploiement d'OTP?

---

## Mise à Jour: Mai 2026

**Items complétés:**
- ✅ César: chiffrement, force brute, IC, chi-squared
- ✅ Vigenère: Kasiski, IC analysis, key recovery
- ✅ Hill: known-plaintext attack 2×2 et 3×3
- ✅ OTP: key reuse vulnerability, crib dragging
- ✅ Tests complets et intégrés

**Prochaine étape:** TP 2 - Cryptographie Symétrique Moderne (RC4, DES, AES)
