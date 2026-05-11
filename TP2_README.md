# TP 2 - Cryptographie Symétrique Moderne

## Vue d'ensemble

Ce TP couvre les **chiffrements symétriques modernes**, comparés aux méthodes classiques du TP 1.

| Algorithme | Taper | Clé | Bloc | État | Notes |
|-----------|-------|-----|------|------|-------|
| **RC4** | Stream | 40-256 bits | Stream | ✗ Cassé | Vulnérable WEP, biais statistique |
| **DES** | Block | 56 bits | 64 bits | ✗ Cassé | Clé trop petite, collision birthay 2^32 blocs |
| **3DES** | Block | 112-168 bits | 64 bits | ~ Accepté | Lent (9× plus lent qu'AES), mais sûr |
| **AES** | Block | 128/192/256 bits | 128 bits | ✓ Sûr | Standard NIST depuis 2001, aucune attaque pratique |

## Structure des fichiers

```
/home/matt-anis/Studies/Crypto/
├── RC4/
│   ├── rc4.py              (Implémentation de base)
│   └── rc4_attacks.py      (NEW) - Vulnérabilités WEP/bias/correlation
├── DES/
│   ├── des.py              (Implémentation de base)
│   └── des_modes.py        (NEW) - ECB/CBC, 3DES, avalanche
├── AES/
│   ├── __init__.py
│   ├── cipher.py           (Implémentation de base)
│   ├── aes_modes.py        (NEW) - ECB/CBC/CTR, clés, nonce reuse
│   └── nist_finalists.py   (NEW) - 5 finalistes NIST
└── tp2_complete.py         (NEW) - Suite de tests intégrée
```

## Exercices couvert

### 2.1 - RC4 (Chiffrement par Flot)

**Objectif:** Comprendre pourquoi RC4 est complètement cassé.

**Fichier:** `RC4/rc4_attacks.py`

**Contenus:**

1. **WEP Vulnerability (Wired Equivalent Privacy)**
   - IV 24 bits + Clé de session → Keystream de ~1.5 milliards d'octets
   - Attaque FMS (Fluhrer-Mantin-Shamir): Récupère clé avec ~1.5M packets
   - Démonstration: IV corrélation avec keystream = weak scheduling

2. **Statistical Bias Analysis**
   - Analyse de 10,000 keystream générés (RC4 KSA)
   - Résultat: 2ème byte biaisé vers 0 (probabilité > aleatoire)
   - Impact: Dégrade sécurité - différencie chiffré de bruit blanc

3. **Keystream Correlation**
   - Même clé + différents IV → keystreams corrélés (PAS indépendants)
   - Attaque: Si plaintext partiellement known → keystream partiel retrouvé
   - Shows pourquoi reuse clé fatal

**Vulnérabilités découvertes:** WEP cassé 2001 (Stubblefield et al), RC4 officiel déprécié RFC 7465 (2015)

---

### 2.2 - DES et Triple-DES

**Objectif:** Comparer ECB vs modes sûrs, comprendre limitations DES (56-bit key).

**Fichier:** `DES/des_modes.py`

**Contenus:**

1. **ECB vs CBC Comparison**
   - ECB: Electronic Code Book (DANGEREUX)
     - Même plaintext bloc → Même ciphertext bloc
     - Pattern preservation: "AAAABBBB" reste reconnaissable chiffré
   - CBC: Cipher Block Chaining (SÛRE)
     - Chaque bloc XOR avec précédent ciphertext
     - Même plaintext → différent ciphertext (IV random)

2. **ECB Weakness Visualization**
   - Plaintext: 8 blocs identiques "AAAAAAAA_"
   - ECB chiffré: Patterns visibles (tous identiques)
   - CBC chiffré: Chacun unique (chaining effet)

3. **CBC IV Sensitivity**
   - IV random = avalanche effect
   - Flip 1 bit IV → ciphertext bloc 1 changes complètement
   - Blocks suivant non affecté (no propagation)
   - Importance: IV must be random ET secret (pas predictable)

4. **3DES Performance**
   - Triple-DES = DES trois fois (key1, key2, key1)
   - Résultat: Clé effectif 112 bits (au lieu 56)
   - Performance: 9× plus lent que DES
   - Utilisation: Accepté pour legacy (migration vers AES recommandée)

**Notes importantes:**
- DES clé 56 bits → 2^56 ≈ 7×10^16 clés → peut être broken par brute force moderne (GPU)
- DES bloc 64 bits → Birthday paradox à ~2^32 blocs (ciphertext overlap possible)
- 3DES sûr en mode CBC/CTR avec IV random, mais trop lent pour nouveau code

---

### 2.3 - AES (Advanced Encryption Standard)

**Objectif:** Implémenter AES modes (ECB/CBC/CTR), démontrer nonce reuse, oracle attacks.

**Fichier:** `AES/aes_modes.py`

**Contenus:**

1. **AES Modes Comparison**
   - **ECB**: Dangereux (même plaintext → même ciphertext)
   - **CBC**: Sûr avec IV random, mais sans authentification
   - **CTR**: Stream cipher mode - élégant et rapide

2. **Key Size Comparison**
   - AES-128: ~2^128 clés, ~10 rounds, security level 128-bit
   - AES-192: ~2^192 clés, ~12 rounds, security level 192-bit
   - AES-256: ~2^256 clés, ~14 rounds, security level 256-bit
   - Performance: AES-128 baseline, AES-256 ~1.2-1.3× lent

3. **Nonce Reuse Vulnerability (CTR mode - CRITIQUE)**
   - CTR: Nonce + Counter → Keystream, plaintext XOR keystream = ciphertext
   - **CATASTROPHE**: Même (key, nonce) utilisé 2 fois → C1 XOR C2 = M1 XOR M2
   - Impact: Plaintext complètement exposé (pas d'autre protection)
   - **Rule**: JAMAIS réutiliser nonce+key pair (même fois, même key)

4. **CBC Avalanche Effect**
   - IV random → ciphertext random
   - Change 1 bit plaintext bloc i → bloc i+1,i+2,... tous affectés
   - Exemple: 128 plaintext bits → 128 ciphertext bits tous changent

5. **Chosen Ciphertext Attack on ECB**
   - Oracle: "Déchiffre ce texte" (ECB mode)
   - Attaque: Construire plaintext secret - byte par byte
   - Exemple: 16-byte secret
     - Encrypt(15 bytes "A" + unknown_1st_byte)
     - Compare résultat avec Encrypt(15 bytes "A" + "A") jusqu'à match
     - Trouvé 1ère byte
     - Idem pour 2nde, 3nde... 16ème
   - Résultat: Secret entièrement retrouvé → **ECB cassé avec oracle**

**Recommandations:**
- ✓ Utilizer AES-256-GCM (authentification incluse)
- ✓ OU AES-256-CBC + HMAC-SHA256
- ✗ JAMAIS ECB
- ✗ JAMAIS CTR sans nonce management (voir ChaCha20-Poly1305)

---

### 2.4 - Les 5 Finalistes NIST

**Objectif:** Décrire, comparer, benchmarker les 5 finalistes AES (1997-2000).

**Fichier:** `AES/nist_finalists.py`

**5 Finalistes:**

1. **Rijndael** (SÉLECTIONNÉ → AES)
   - Type: SPN (Substitution-Permutation Network)
   - Rounds: 10 (AES-128) à 14 (AES-256)
   - Taille clé: Flexible (128/192/256 bits)
   - Taille bloc: Flexible (128/192/256 bits)
   - Avantages: Rapide, élégant, hardware-friendly (AES-NI)
   - Performance: ~3.5 cycles/byte (Intel moderne)
   - **Choix final**: Équilibre perf + sécurité + elegance

2. **Twofish** (Rejeted - trop mémoire intensif)
   - Type: Feistel
   - Rounds: 16
   - Taille clé: 128/192/256 bits
   - Caractéristique: 4KB S-boxes (lookup tables)
   - Problème: Cache misses en embedded, trop d'état à charger
   - Performance: More variable than Rijndael
   - Raison rejet: Complexité + memory overhead

3. **Serpent** (Rejected - trop lent) 
   - Type: SPN
   - Rounds: 32 (ultra-conservateur)
   - Taille clé: 128/192/256 bits
   - Caractéristique: 7 boîtes S parallèles, marge sécurité massive
   - Performance: 5-10× plus lent que Rijndael
   - Philosophy: "Maximum security, who cares speed"
   - Raison rejet: Overkill (Rijndael equally secure, much faster)

4. **RC6** (Rejected - complexité)
   - Type: Feistel
   - Rounds: 20
   - Taille clé: 128/192/256 bits
   - Caractéristique: Rotations variables par clé (data-dependent)
   - Problème: Complexité additions (word-size dépendent)
   - Raison rejet: Plus complexe que Rijndael avec benefit zero

5. **MARS** (Rejected - overcomplicated)
   - Type: Hybrid (SPN + Feistel)
   - Rounds: 32
   - Taille clé: 128/192/256 bits
   - Caractéristique: Keying massif (mix SPN + Feistel)
   - Problème: Trop compliqué, not elegant, slow in software
   - Raison rejet: Rijndael simpler + better performance

**Comparaison Table:**

| Critère | Rijndael | Twofish | Serpent | RC6 | MARS |
|---------|----------|---------|---------|-----|------|
| Type | SPN | Feistel | SPN | Feistel | Hybrid |
| Rounds | 10-14 | 16 | 32 | 20 | 32 |
| Clé (bits) | 128-256 | 128-256 | 128-256 | 128-256 | 128-256 |
| Bloc | 128 | 128 | 128 | 128 | 128 |
| Performance | ★★★★★ | ★★★☆☆ | ★★☆☆☆ | ★★★☆☆ | ★★☆☆☆ |
| Mémoire | Low | Very High | Medium | Medium | High |
| Complexité | Simple | Medium | Medium | Complex | Complex |
| Sécurité | ✓ Safe | ✓ Safe | ✓ Safe+ | ✓ Safe | ✓ Safe |
| Status | **SÉLECTIONNÉ** | Rejected | Rejected | Rejected | Rejected |

**Raison du choix Rijndael:**
1. **Vitesse**: Meilleures performances software + hardware (AES-NI)
2. **Elegance**: Architecture mathematically simple, easy to analyze
3. **Flexibility**: Variable key/block sizes (though AES fixes to 128)
4. **Implementation**: Straightforward, no complex dependencies
5. **Scalability**: Scales to AES-NI, SIMD, ASIC sans problème

**25+ ans retrospective (2001-2026):**
- Rijndael/AES: No practical attacks found
- Theoretical attacks: Biclique (slightly better than brute force, but impractical)
- Hardware security: AES-NI protects contre timing/cache attacks
- Usage: Standard-de-facto partout (cryptographic backbone)
- Decision: Completely justified, proven correct

---

## Exécution

### Lancer la suite complète TP2:

```bash
cd /home/matt-anis/Studies/Crypto
python tp2_complete.py
```

### Lancer exercices individuels:

```bash
# RC4
python RC4/rc4_attacks.py

# DES
python DES/des_modes.py

# AES
python AES/aes_modes.py

# NIST Finalists
python AES/nist_finalists.py
```

### Ou dans Python REPL:

```python
from RC4.rc4_attacks import wep_vulnerability_demo
wep_vulnerability_demo()
```

---

## Dépendances

Voir `requirements.txt`:
- `pycryptodome` - Crypto.Cipher (DES, AES)
- `cryptography` - Keyx derivation
- `sympy` - (pour TP1, pas utilisé TP2)

Install: `pip install -r requirements.txt`

---

## Vulnérabilités Clés

### RC4 - Complètement Cassé
- **WEP Vulnerability**: Clé 128-bit attacked with ~1.5M packets (Fluhrer et al 2001)
- **Statistical Bias**: 2nd byte biaisé, autres positions anormales
- **Key Reuse**: Même clé+IV → plaintext recovered par XOR
- **Status**: RFC 7465 (2015) prohibited - NEVER use

### DES - Brute Force Possible
- **56-bit key**: 2^56 ≈ 7×10^16 - GPU crack en ~1 jour (2026)
- **64-bit block**: Birthday paradox ciphertext overlap à ~2^32 blocs
- **ECB weakness**: Pattern preservation
- **Status**: Deprecated (use only legacy)

### 3DES - Acceptable but Slow
- **112-bit key**: 3× DES (K1, K2, K1 again) → 112 effective bits
- **Performance**: 9× slower than AES
- **Security**: OK in CBC/CTR + random IV
- **Status**: Migration to AES recommended

### AES - No known attacks (2026)
- **128/192/256 bits**: All safe against brute force (128-bit = 2^128 = 10^39)
- **256-bit blocks**: No birthday paradox before 2^64 blocks
- **ECB weakness**: Still has pattern issue (use CBC/CTR/GCM)
- **CTR nonce reuse**: CRITICAL - never reuse (key, nonce) pair
- **Status**: STANDARD - use AES-256-GCM for authentic + confidential

---

## Résumé: Pour utiliser en production

```
╔════════════════════════════════════════════════════╗
║   CHIFFREMENT SYMÉTRIQUE - RECOMMANDATIONS (2026)  ║
╠════════════════════════════════════════════════════╣
║                                                    ║
║  CONFIDENTIEL + AUTHENTIFICATION:                 ║
║  ✓ AES-256-GCM (MEILLEUR CHOIX)                    ║
║                                                    ║
║  CONFIDENTIEL SEULEMENT:                          ║
║  ✓ AES-256-CTR + HMAC-SHA256 (separé)            ║
║  ✓ ChaCha20-Poly1305 (alternative)               ║
║                                                    ║
║  LEGACY/COMPATIBILITY:                            ║
║  ~ 3DES-CBC + HMAC (migrer ASAP)                  ║
║                                                    ║
║  JAMAIS UTILISER:                                ║
║  ✗ RC4 (complètement cassé)                       ║
║  ✗ DES (clé trop petite)                          ║
║  ✗ AES-ECB (pattern preservation)                 ║
║  ✗ AES-CTR sans nonce management (fatal reuse)   ║
║                                                    ║
╚════════════════════════════════════════════════════╝
```

---

## Ressources

- **NIST FIPS 197**: AES Standard (2001)
- **RFC 3394**: AES Key Wrap (2002)
- **RFC 7539**: ChaCha20 and Poly1305 (2015)
- **RFC 7465**: Prohibiting RC4 Cipher Suites (2015)
- **Paper**: "Fluhrer, Mantin, Shamir" - WEP break (2001)
- **Biclique**: Bogdanov et al - AES attack (theoretical, ~2^126.1 < 2^128)
