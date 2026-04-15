# 🔐 DES - Data Encryption Standard

Implementation complète de l'algorithme DES en Python, incluant les modes ECB et CBC.

---

## 📋 Table des Matières

- [Description](#description)
- [Algorithme DES](#algorithme-des)
- [Structure du Code](#structure-du-code)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Exemples](#exemples)
- [Sécurité](#sécurité)

---

## Description

Ce projet implémente l'algorithme de chiffrement symétrique **DES (Data Encryption Standard)**
from scratch en Python pur, sans bibliothèques cryptographiques externes.

- ✅ Chiffrement et déchiffrement DES complet
- ✅ Mode **ECB** (Electronic Codebook)
- ✅ Mode **CBC** (Cipher Block Chaining)
- ✅ Padding PKCS#5
- ✅ Génération des 16 sous-clés

---

## Algorithme DES

### Vue d'ensemble

DES est un algorithme de chiffrement par blocs publié en 1977 (FIPS 46).
Il opère sur des **blocs de 64 bits** avec une **clé de 56 bits** (64 bits avec bits de parité).
