"""
ex1_tcp/client.py  —  Exercice 6.1 : Sécurisation par Sockets TCP/IP
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import socket
from common.crypto_utils import (
    generate_aes_key, deserialize_public_key,
    rsa_encrypt, aes_encrypt, aes_decrypt,
    compute_hmac, verify_hmac
)
from common.protocol import send_bytes, recv_bytes

HOST = "127.0.0.1"
PORT = 5000


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print(f"[+] Connecté au serveur {HOST}:{PORT}")

        # ── Étape 1 : recevoir la clé publique RSA du serveur ────────────
        pub_pem   = recv_bytes(sock)
        server_pk = deserialize_public_key(pub_pem)
        print("[*] Clé publique RSA du serveur reçue.")

        # ── Étape 2 : générer et envoyer la clé AES chiffrée ─────────────
        aes_key  = generate_aes_key()          # 256 bits
        hmac_key = generate_aes_key(32)        # clé HMAC séparée

        enc_aes = rsa_encrypt(server_pk, aes_key)
        send_bytes(sock, enc_aes)
        send_bytes(sock, hmac_key)
        print(f"[*] Clé AES envoyée (chiffrée RSA) : {aes_key.hex()[:16]}…\n")

        # ── Étape 3 : envoyer des messages sécurisés ─────────────────────
        print("Tapez vos messages (ou 'quit' pour quitter) :")
        while True:
            msg = input("> ").strip()
            if not msg:
                continue

            payload    = msg.encode() if msg != "quit" else b"__EXIT__"
            ciphertext = aes_encrypt(aes_key, payload)
            mac        = compute_hmac(hmac_key, ciphertext)
            send_bytes(sock, ciphertext)
            send_bytes(sock, mac)

            if msg == "quit":
                break

            # Lire la réponse
            enc_resp = recv_bytes(sock)
            mac_resp = recv_bytes(sock)
            if verify_hmac(hmac_key, enc_resp, mac_resp):
                print(f"[Serveur] {aes_decrypt(aes_key, enc_resp).decode()}")
            else:
                print("[!] Réponse du serveur : HMAC invalide !")


if __name__ == "__main__":
    main()
