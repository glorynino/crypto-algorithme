"""
ex1_tcp/server.py  —  Exercice 6.1 : Sécurisation par Sockets TCP/IP
======================================================================
Protocole d'établissement de session sécurisée :

  1. B envoie sa clé publique RSA à A
  2. A génère une clé AES aléatoire, la chiffre avec la clé publique de B
     et envoie : RSA_B(aes_key) + HMAC_key (clé d'intégrité)
  3. Chaque message est ensuite protégé :
       - Chiffré avec AES-256-CBC
       - Authentifié avec HMAC-SHA256
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import socket
from common.crypto_utils import (
    generate_rsa_keypair, serialize_public_key,
    rsa_decrypt, aes_decrypt, verify_hmac
)
from common.protocol import send_bytes, recv_bytes

HOST = "127.0.0.1"
PORT = 5000


def handle_client(conn: socket.socket, addr):
    print(f"[+] Connexion de {addr}")

    # ── Étape 1 : générer et envoyer la clé publique RSA ──────────────────
    private_key, public_key = generate_rsa_keypair()
    send_bytes(conn, serialize_public_key(public_key))
    print("[*] Clé publique RSA envoyée.")

    # ── Étape 2 : recevoir la clé AES chiffrée par RSA ───────────────────
    encrypted_aes_key = recv_bytes(conn)
    aes_key = rsa_decrypt(private_key, encrypted_aes_key)

    hmac_key = recv_bytes(conn)                # clé HMAC en clair (canal "établi")
    print(f"[*] Clé AES reçue : {aes_key.hex()[:16]}…")

    # ── Étape 3 : boucle de réception de messages sécurisés ──────────────
    print("[*] Session sécurisée établie. En attente de messages…\n")
    while True:
        try:
            ciphertext = recv_bytes(conn)
            mac        = recv_bytes(conn)

            if not verify_hmac(hmac_key, ciphertext, mac):
                print("[!] HMAC invalide — message rejeté.")
                continue

            plaintext = aes_decrypt(aes_key, ciphertext)
            message   = plaintext.decode()

            if message == "__EXIT__":
                print("[*] Client déconnecté proprement.")
                break

            print(f"[A→B] {message}")

            # Echo chiffré
            response   = f"Echo: {message}".encode()
            enc_resp   = aes_decrypt.__module__  # juste pour ne pas réimporter
            # on utilise directement aes_encrypt du module
            from common.crypto_utils import aes_encrypt, compute_hmac
            enc_resp   = aes_encrypt(aes_key, response)
            mac_resp   = compute_hmac(hmac_key, enc_resp)
            send_bytes(conn, enc_resp)
            send_bytes(conn, mac_resp)

        except ConnectionError:
            break

    conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"[Serveur] En écoute sur {HOST}:{PORT} …")
        conn, addr = srv.accept()
        with conn:
            handle_client(conn, addr)


if __name__ == "__main__":
    main()
