"""
ex4_vote/vote.py  —  Exercice 6.4 : Vote électronique sécurisé (Homomorphisme)
===============================================================================
Implémentation du schéma de Paillier (chiffrement partiellement homomorphe).

Propriété clé :
  Enc(a) * Enc(b) mod n² = Enc(a + b)  → addition sur les votes chiffrés

Protocole :
  1. L'autorité génère une paire de clés Paillier (pk, sk)
  2. Chaque votant chiffre son vote (0 ou 1) avec pk
  3. Le serveur additionne les chiffrés homomorphiquement → Enc(total)
  4. L'autorité déchiffre Enc(total) avec sk → résultat final
  5. Un QR code est généré pour chaque reçu de vote
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import random
import math
import json
import hashlib

try:
    import qrcode
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    print("[!] qrcode non installé. pip install qrcode[pil]")


# ══════════════════════════════════════════════════════════════════════════════
#  Schéma de Paillier — implémentation minimale
# ══════════════════════════════════════════════════════════════════════════════

def _is_prime(n: int, k: int = 20) -> bool:
    """Test de primalité Miller-Rabin."""
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        p = random.getrandbits(bits) | (1 << bits - 1) | 1
        if _is_prime(p):
            return p


def _lcm(a: int, b: int) -> int:
    return a * b // math.gcd(a, b)


def _L(x: int, n: int) -> int:
    return (x - 1) // n


class PaillierPublicKey:
    def __init__(self, n: int, g: int):
        self.n  = n
        self.g  = g
        self.n2 = n * n

    def encrypt(self, m: int) -> int:
        """Chiffre un entier m ∈ [0, n)."""
        assert 0 <= m < self.n
        while True:
            r = random.randrange(1, self.n)
            if math.gcd(r, self.n) == 1:
                break
        return pow(self.g, m, self.n2) * pow(r, self.n, self.n2) % self.n2

    def add_encrypted(self, c1: int, c2: int) -> int:
        """Additionne deux chiffrés : Enc(m1) ⊕ Enc(m2) = Enc(m1 + m2)."""
        return c1 * c2 % self.n2

    def to_dict(self) -> dict:
        return {"n": self.n, "g": self.g}


class PaillierPrivateKey:
    def __init__(self, lam: int, mu: int, pub: PaillierPublicKey):
        self.lam = lam
        self.mu  = mu
        self.pub = pub

    def decrypt(self, c: int) -> int:
        """Déchiffre un chiffré c."""
        n, n2 = self.pub.n, self.pub.n2
        x = pow(c, self.lam, n2)
        l = _L(x, n)
        return l * self.mu % n


def generate_paillier_keys(bits: int = 512):
    """Génère une paire de clés Paillier."""
    p = _gen_prime(bits // 2)
    q = _gen_prime(bits // 2)
    while p == q:
        q = _gen_prime(bits // 2)

    n   = p * q
    lam = _lcm(p - 1, q - 1)
    g   = n + 1                          # choix simplifié : g = n+1
    mu  = pow(_L(pow(g, lam, n * n), n), -1, n)

    pub = PaillierPublicKey(n, g)
    prv = PaillierPrivateKey(lam, mu, pub)
    return pub, prv


# ══════════════════════════════════════════════════════════════════════════════
#  Vote électronique
# ══════════════════════════════════════════════════════════════════════════════

class VotingAuthority:
    """Autorité centrale : génère les clés et déchiffre le résultat."""

    def __init__(self):
        print("[Autorité] Génération des clés Paillier…")
        self.pub, self.prv = generate_paillier_keys(bits=512)
        print(f"[Autorité] Clé publique n = {str(self.pub.n)[:30]}…")

    def tally(self, encrypted_votes: list) -> int:
        """Additionne homomorphiquement tous les votes chiffrés, déchiffre le total."""
        if not encrypted_votes:
            return 0
        # Enc(v1) * Enc(v2) * … = Enc(v1 + v2 + …)
        total_enc = encrypted_votes[0]
        for ev in encrypted_votes[1:]:
            total_enc = self.pub.add_encrypted(total_enc, ev)
        return self.prv.decrypt(total_enc)


class VotingServer:
    """Serveur de collecte : accumule les bulletins chiffrés."""

    def __init__(self, public_key: PaillierPublicKey):
        self.pk             = public_key
        self.encrypted_votes: list = []
        self.receipts:        list = []

    def submit_vote(self, encrypted_vote: int, voter_id: str) -> str:
        """
        Accepte un vote chiffré.
        Retourne un reçu (hash du chiffré) pour le votant.
        """
        self.encrypted_votes.append(encrypted_vote)
        receipt = hashlib.sha256(str(encrypted_vote).encode()).hexdigest()
        self.receipts.append({"voter": voter_id, "receipt": receipt})
        print(f"[Serveur] Vote de {voter_id} enregistré. Reçu: {receipt[:12]}…")
        return receipt


class Voter:
    """Représente un votant anonyme."""

    def __init__(self, voter_id: str, public_key: PaillierPublicKey):
        self.voter_id = voter_id
        self.pk       = public_key

    def cast_vote(self, choice: int) -> tuple:
        """
        choice : 1 = OUI, 0 = NON
        Retourne (chiffré, reçu QR code path)
        """
        assert choice in (0, 1), "Le vote doit être 0 ou 1."
        enc = self.pk.encrypt(choice)
        print(f"[{self.voter_id}] Vote '{choice}' chiffré.")
        return enc

    def generate_qr(self, receipt: str, path: str = None):
        """Génère un QR code contenant le reçu de vote."""
        if not QR_AVAILABLE:
            print(f"[{self.voter_id}] QR non disponible. Reçu : {receipt}")
            return None

        path = path or f"qr_{self.voter_id}.png"
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(json.dumps({"voter": self.voter_id, "receipt": receipt}))
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(path)
        print(f"[{self.voter_id}] QR code sauvegardé : {path}")
        return path


# ══════════════════════════════════════════════════════════════════════════════
#  Démonstration complète
# ══════════════════════════════════════════════════════════════════════════════

def demo():
    print("=" * 60)
    print("  VOTE ÉLECTRONIQUE SÉCURISÉ — Schéma de Paillier")
    print("=" * 60)

    # 1. Autorité crée les clés
    authority = VotingAuthority()
    server    = VotingServer(authority.pub)

    # 2. Définir les votants et leurs choix
    votes_data = [
        ("Alice",   1),   # OUI
        ("Bob",     1),   # OUI
        ("Charlie", 0),   # NON
        ("Diana",   1),   # OUI
        ("Eve",     0),   # NON
    ]
    expected_yes = sum(v for _, v in votes_data)

    print(f"\n[Info] {len(votes_data)} votants. OUI attendus : {expected_yes}\n")

    # 3. Chaque votant chiffre et soumet son vote
    for voter_id, choice in votes_data:
        voter     = Voter(voter_id, authority.pub)
        enc_vote  = voter.cast_vote(choice)
        receipt   = server.submit_vote(enc_vote, voter_id)
        voter.generate_qr(receipt, path=f"ex4_vote/qr_{voter_id}.png")

    # 4. L'autorité décompte les votes chiffrés
    print(f"\n[Autorité] Décompte des {len(server.encrypted_votes)} votes chiffrés…")
    result = authority.tally(server.encrypted_votes)

    print("\n" + "=" * 60)
    print(f"  RÉSULTAT : {result} OUI / {len(votes_data) - result} NON")
    print(f"  Vérification : {result == expected_yes} ✓" if result == expected_yes
          else f"  ERREUR : attendu {expected_yes}, obtenu {result}")
    print("=" * 60)


if __name__ == "__main__":
    demo()
