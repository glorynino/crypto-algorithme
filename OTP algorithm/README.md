# 🔐 One-Time Pad (OTP)

## 📌 Description

Le One-Time Pad (OTP) est un algorithme de chiffrement symétrique qui offre une **sécurité parfaite**, concept introduit par Claude Shannon.

Il consiste à chiffrer un message en utilisant une clé :
- totalement aléatoire
- de même longueur que le message
- utilisée une seule fois

---

## 🧠 Principe

Le chiffrement repose sur l'opération XOR (OU exclusif).

### 🔒 Chiffrement

C = M ⊕ K

### 🔓 Déchiffrement

M = C ⊕ K

Avec :
- M : message (plaintext)
- K : clé (key)
- C : message chiffré (ciphertext)

---

## ⚙️ Conditions de sécurité

Pour garantir une sécurité parfaite, les conditions suivantes doivent être respectées :

- 🔑 La clé doit avoir la même longueur que le message
- 🎲 La clé doit être parfaitement aléatoire
- 🔁 La clé ne doit être utilisée qu'une seule fois
- 🔒 La clé doit rester secrète

---

## 💡 Exemple

Message (M) : 1011  
Clé (K)     : 1101  

Chiffrement :  
1011 ⊕ 1101 = 0110  

Déchiffrement :  
0110 ⊕ 1101 = 1011  

---

## ⚠️ Limites

Malgré sa sécurité parfaite, le OTP présente des contraintes importantes :

- Nécessite une clé aussi longue que le message
- Difficulté de générer une vraie clé aléatoire
- Problème de distribution sécurisée de la clé
- Gestion complexe (ne jamais réutiliser une clé)

---

## 💣 Attention : réutilisation de la clé

Si la même clé est utilisée pour chiffrer deux messages :

C1 = M1 ⊕ K  
C2 = M2 ⊕ K  

Alors :

C1 ⊕ C2 = M1 ⊕ M2  

➡️ Cela permet de retrouver des informations sur les messages.

---

## 📚 Conclusion

Le One-Time Pad est le seul système de chiffrement prouvé comme étant **parfaitement sécurisé**, mais son utilisation pratique est limitée par des contraintes logistiques importantes.

---

## 🚀 Utilisation

Ce projet propose une implémentation simple du One-Time Pad pour :
- chiffrer un message
- déchiffrer un message

