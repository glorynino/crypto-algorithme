# TP 3 - Cryptographie Asymétrique Moderne

## Vue d'ensemble

Ce TP couvre les **chiffrements asymétriques** (public-key cryptography), essentiels pour l'authentification, les signatures numériques, et l'échange de clés.

| Algorithme | Type | Fondation | Sécurité | Notes |
|-----------|------|-----------|---------|-------|
| **DH** | Key Exchange | Discrete Log | ✓ Sûr | Base pour ECDH, pas d'authentification |
| **RSA** | Encryption + Signature | Factorization | ✓ Sûr (avec padding) | Standard ancien, toujours utilisé |
| **ElGamal** | Encryption | Discrete Log | ◐ Fragile | Homomorphe, attaques spécifiques |
| **ECC** | DH + Signature | Elliptic Curve DLP | ✓ Sûr | Moderne, clés courtes, TLS 1.3 |

## Structure des fichiers

```
/home/matt-anis/Studies/Crypto/
├── DH/
│   ├── dh.py              (Implémentation Diffie-Hellman)
│   └── dh_attacks.py      (NEW) - Pohlig-Hellman, MITM, subgroups
├── RSA/
│   ├── rsa.py             (Implémentation RSA textbook)
│   └── rsa_attacks.py     (NEW) - Small e, common modulus, oracle
├── ElGamal/
│   ├── elgamal.py         (Implémentation ElGamal)
│   └── elgamal_attacks.py (NEW) - Homomorphic, subgroups, distinguishing
├── ECC/
│   ├── ecc.py             (ECDH et ECDSA basiques)
│   └── ecc_attacks.py     (NEW) - Timing, twist, nonce reuse
└── tp3_complete.py        (NEW) - Suite de tests intégrée
```

## Exercices couvert

### 3.1 - Diffie-Hellman (Échange de Clés)

**Objectif:** Comprendre fondamentaux de la crypto asymétrique, pourquoi DH n'est pas authenticité.

**Fichier:** `DH/dh_attacks.py`

**Contenus:**

1. **Pohlig-Hellman Attack**
   - Factorize p-1 en petits nombres premiers
   - CRT combine résultats
   - Récupère clé privée (ou partial key)
   - Défense: safre primes (p = 2q + 1)

2. **Small Subgroup Attack**
   - Si g a petit ordre
   - Peut forcer réponses petits groupe
   - Apprend clé mod ordre petit
   - CRT combine

3. **MITM Attack (No Authentication)**
   - Eve intercepts et se fait passer pour les deux côtés
   - Protocol works correctament but compromised
   - Pourquoi authentification critique

4. **Passive Eavesdropping**
   - Attacker voit clés publiques A, B
   - Mais ne peut pas calculer g^(ab)
   - Discrete log hard

5. **Replay Attack**
   - Reuse même clé pour plusieurs sessions
   - Démontre pourquoi ephemeral keys necessaire

**Leçons clés:**
- DH secure contre passive eavesdropping
- Pas secure contre MITM sans authentification
- Parameters doivent avoir large prime factors (safe primes)
- Modern: ECDH (not DH), dans TLS 1.3

---

### 3.2 - RSA (Chiffrement et Signature)

**Objectif:** Comprendre vulnerabilités RSA textbook, pourquoi padding critical.

**Fichier:** `RSA/rsa_attacks.py`

**Contenus:**

1. **Small Exponent Attack (e=3)**
   - Si plaintext petit, m^3 < n
   - Pas réduction modulo
   - Take cube root

2. **Common Modulus Attack**
   - Même n, différentes (e1, e2)
   - Si gcd(e1, e2) = 1
   - Recover plaintext SANS clé privée!
   - c1^x · c2^y = m (Extended GCD)

3. **Related Message Attack**
   - Si attacker sait m2 = k·m1
   - Peut cryptanalyzer

4. **Textbook RSA Homomorphic Property**
   - E(m1) × E(m2) = E(m1 × m2)
   - Attacker peut manipuler ciphertexts
   - Basis pour bleichenbacher attacks

5. **Padding Oracle / Bleichenbacher**
   - Si erreur message "padding invalid"
   - Oracle révèle information bits
   - O(log n) appels oracle → récupère plaintext

6. **Signature Attacks**
   - Textbook RSA signature: sig(m) = m^d
   - Multiplicative: sig(m1)·sig(m2) = sig(m1·m2)
   - No randomness (replay attacks)
   - Défense: hash + padding (PSS)

7. **Broadcast Attack (Hastad)**
   - e=3, même message to 3 recipients
   - CRT combine c1, c2, c3
   - Take cube root

**Recommandations:**
- ✓ Use e = 65537 (not 3)
- ✓ Strong primes (safe primes)
- ✓ AES-256-GCM (not RSA for encryption alone)
- ✓ RSA signatures: hash + PSS padding
- ✗ Textbook RSA
- ✗ PKCS#1 v1.5 padding (leaks via oracle)
- ✗ Fixed e=3 or small e

---

### 3.3 - ElGamal (Chiffrement à Clés Publiques)

**Objectif:** Cryptosystème basé DH, attaques spécifiques, pourquoi deprecated.

**Fichier:** `ElGamal/elgamal_attacks.py`

**Contenus:**

1. **Homomorphic Property**
   - E(m1) · E(m2) = E(m1 · m2 mod p)
   - Attacker peut générer ciphertexts sans key
   - Vote manipulation, chosen plaintext attacks
   - Défense: authenticate, hash, add redundancy

2. **Small Subgroup Attack**
   - If g a petit ordre
   - Learn m mod small factor
   - CRT combine
   - Défense: safe primes

3. **Re-encryption Tracking**
   - Proxy re-encryption vulnérable
   - Attacker peut détecter re-encryption
   - Information leakage
   - Défense: blind transformation

4. **Passive Key Recovery**
   - CRT + small subgroups
   - O(log n) subgroups → full key
   - Advanced attack
   - Défense: use RFC 7919 safe primes (p = 2q+1)

5. **Distinguishing Attack**
   - No semantic security
   - Can compute quadratic residue check
   - Leak: is m quadratic residue?
   - Attacker wins >50% probability
   - Défense: padding, hashing

**Recommandations:**
- ✗ Never use textbook ElGamal
- ~ Use DHIES (DH Integratedcryption Scheme)
- ✓ Use ECIES modern (Elliptic Curve)
- ✓ Hash + randomization

---

### 3.4 - Elliptic Curve Cryptography

**Objectif:** Modern cryptography, ECDH/ECDSA, advantages over RSA/DH.

**Fichier:** `ECC/ecc_attacks.py`

**Contenus:**

1. **Small Subgroup Attack**
   - Si curve a cofactor h > 1
   - Peut send small-order points
   - Learn d mod order(point)
   - CRT combine
   - Défense: cofactor clearing, h=1 curves

2. **Anomalous Curve Attack**
   - Curve avec #E(Fp) = p (très rare)
   - Isomorphic à additive group
   - Discrete log becomes polynomial
   - Semaev-Silverman-Smart attack
   - Défense: verified, reviewed curves

3. **Twist Attack (Invalid Curve)**
   - Send points from twist curve E'
   - Naive implementation doesn't verify
   - Learn d mod factors of #E'
   - Défense: always validate y^2 = x^3+ax+b

4. **Timing Attack**
   - Scalar multiplication time varies by key
   - More 1-bits → more time
   - Remote timing via network latency
   - Recover d bit-by-bit
   - Défense: constant-time Montogomery ladder, unified formulas

5. **Rogue Curve Attack**
   - If parameters trapdoored
   - Can include backdoor
   - Example: Dual EC DRBG (NSA)
   - Défense: use rigorously reviewed curves

6. **ECDSA Nonce Reuse**
   - If k reused for two messages
   - Can recover d in one equation
   - CRITICAL: k MUST be unique
   - Real disaster: PS3 jailbreak (2010)
   - Défense: RFC 6979 deterministic, or EdDSA

**Standard Curves:**
- NIST P-256 / P-384 / P-521
- Curve25519 / Curve448 (modern)
- SafeCurves criteria (safecurves.cr.yp.to)

**Avantages vs RSA/DH:**
- ✓ 256-bit ECC ≈ 3072-bit RSA (security level)
- ✓ Faster operations
- ✓ Smaller signatures (64B vs 512B)
- ✓ No known subexponential attacks
- ✓ Modern standard (TLS 1.3, Signal, Bitcoin)

**Recommandations:**
- ✓ X25519 / X448 key exchange (ECDH)
- ✓ Ed25519 signatures (EdDSA)
- ✓ Verified implementations (libsodium, NaCl, TweetNaCl)
- ✗ Homemade implementations
- ✗ Unverified curves
- ~ ECDSA if RFC 6979 used

---

## Exécution

### Lancer la suite complète TP3:

```bash
cd /home/matt-anis/Studies/Crypto
python tp3_complete.py
```

### Lancer exercices individuels:

```bash
# DH
python DH/dh.py
python DH/dh_attacks.py

# RSA
python RSA/rsa.py
python RSA/rsa_attacks.py

# ElGamal
python ElGamal/elgamal.py
python ElGamal/elgamal_attacks.py

# ECC
python ECC/ecc.py
python ECC/ecc_attacks.py
```

---

## Dépendances

Voir `requirements.txt`:
- `sympy` - Mathematical operations (déjà installé TP1)
- `pycryptodome` - Pour futures modules
- Standard library: `random`, `hashlib`, etc.

Install: `pip install -r requirements.txt`

---

## Vulnérabilités Majeures

### Diffie-Hellman
- ✗ Parameters validation critical (small subgroup attacks)
- ✗ No authentication (MITM attacks)
- ✗ Perfect Forward Secrecy requires ephemeral keys

### RSA
- ✗ Requires padding (OAEP for encryption, PSS for signatures)
- ✗ Small exponent (e=3) catastrophic
- ✗ Textbook RSA completely broken
- ✓ 2048+ bit keys safe against brute force
- ~ Still acceptable for signatures (with padding)

### ElGamal
- ✗ Homomorphic property enables attacks
- ✗ No semantic security
- ✗ Easy to break if parameters not safe primes
- ✗ NEVER use in practice
- ~ Use DHIES for practical DH encryption
- ✓ Use ECIES (Elliptic Curve) instead

### ECC  
- ✓ No subexponential attacks known
- ✓ Smaller keys (256-bit ≈ 3072-bit RSA)
- ~ Implementation pitfalls (timing, twist, nonce reuse)
- ~ Parameter selection important
- ✓ Modern standard (TLS 1.3, Signal)
- ✓ EdDSA (Ed25519) best practice for signatures

---

## Résumé: Pour utiliser en production

```
╔═══════════════════════════════════════════════════════╗
║   CHIFFREMENT ASYMÉTRIQUE - RECOMMANDATIONS (2026)    ║
╠═══════════════════════════════════════════════════════╣
║                                                       ║
║  CLÉ EXCHANGE (Handshake):                           ║
║  ✓ X25519 / X448 (ECDH, moderne)                     ║
║  ~ RFC 7919 FFDH (compatible, legacy)                ║
║  ✗ Static DH (pas forward secrecy)                   ║
║                                                       ║
║  CHIFFREMENT:                                        ║
║  ✓ Hybrid: ECDH + AES-256-GCM                        ║
║  ~ RSA-OAEP + AES-256-GCM (legacy)                   ║
║  ✗ Textbook RSA / ElGamal                            ║
║                                                       ║
║  SIGNATURES:                                         ║
║  ✓ Ed25519 (EdDSA) - moderne, simple, sûr           ║
║  ✓ ECDSA-P256 - standard                            ║
║  ~ RSA-PSS - acceptable                             ║
║  ✗ Textbook RSA signature                           ║
║  ✗ ECDSA avec k non-déterministe                    ║
║                                                       ║
║  CRYPTOGRAPHIE ASYMÉTRIQUE À VENIR (2030+):         ║
║  • Post-Quantum (PQC):                              ║
║    - Lattice: Kyber (KEM), Dilithium (DSA)          ║
║    - Hybrid: ECC + PQC transition                    ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
```

---

## Ressources

- **RFC 3526**: DH Groups for IPSEC
- **RFC 7919**: FFC Safe Primes for TLS
- **FIPS 186-4**: DSA, ECDSA standards
- **NIST SP 800-56A**: ECC Key Agreement
- **SafeCurves**: safecurves.cr.yp.to - critères sécurité courbes
- **Handbook of ECC**: Hankerson, Menezes, Vanstone
- **Understanding Cryptography**: Paar & Pelzl
