"""
ex3_udp_chat/server.py  —  Exercice 6.3 : Sécurisation sur Wi-Fi / UDP
========================================================================
Application de chat sécurisée sur UDP.

Spécificités UDP :
  - Sans connexion → on intègre un numéro de séquence anti-rejeu
  - La clé AES est échangée via un premier paquet RSA (handshake)
  - Chaque datagramme : [seq:4B] + [ciphertext] + [hmac:32B]
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import socket
import struct
import threading
from common.crypto_utils import (
    generate_rsa_keypair, serialize_public_key,
    rsa_decrypt, aes_decrypt, verify_hmac, aes_encrypt, compute_hmac
)

HOST = "0.0.0.0"
PORT = 5001
MAX_DGRAM = 65535


def pack_message(seq: int, ciphertext: bytes, mac: bytes) -> bytes:
    """[seq 4B] + [len_ct 4B] + [ciphertext] + [mac 32B]"""
    return struct.pack(">II", seq, len(ciphertext)) + ciphertext + mac


def unpack_message(data: bytes):
    seq, ct_len = struct.unpack(">II", data[:8])
    ciphertext  = data[8 : 8 + ct_len]
    mac         = data[8 + ct_len :]
    return seq, ciphertext, mac


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"[Serveur UDP Chat] En écoute sur {HOST}:{PORT}")

    # ── Handshake RSA ──────────────────────────────────────────────────────
    private_key, public_key = generate_rsa_keypair()
    pub_pem = serialize_public_key(public_key)

    # Attendre HELLO du client
    data, client_addr = sock.recvfrom(MAX_DGRAM)
    if data != b"HELLO":
        print("[!] Handshake invalide.")
        return
    print(f"[+] Client : {client_addr}")

    # Envoyer clé publique
    sock.sendto(pub_pem, client_addr)

    # Recevoir clé AES chiffrée + clé HMAC
    enc_aes, _  = sock.recvfrom(MAX_DGRAM)
    hmac_raw, _ = sock.recvfrom(MAX_DGRAM)
    aes_key     = rsa_decrypt(private_key, enc_aes)
    hmac_key    = hmac_raw   # transmise chiffrée dans un vrai scénario
    sock.sendto(b"OK", client_addr)
    print("[*] Session UDP sécurisée établie.\n")

    # ── Boucle chat ───────────────────────────────────────────────────────
    expected_seq = 0
    server_seq   = 0

    def receive_loop():
        nonlocal expected_seq
        while True:
            data, addr = sock.recvfrom(MAX_DGRAM)
            if addr != client_addr:
                continue
            if data == b"__BYE__":
                print("\n[*] Client déconnecté.")
                return

            seq, ciphertext, mac = unpack_message(data)

            # Anti-rejeu
            if seq < expected_seq:
                print(f"[!] Paquet rejoué détecté (seq={seq}), ignoré.")
                continue
            expected_seq = seq + 1

            if not verify_hmac(hmac_key, ciphertext, mac):
                print(f"[!] HMAC invalide (seq={seq}), ignoré.")
                continue

            msg = aes_decrypt(aes_key, ciphertext).decode()
            print(f"\r[Client] {msg}\n[Vous]> ", end="", flush=True)

    t = threading.Thread(target=receive_loop, daemon=True)
    t.start()

    while True:
        msg = input("[Vous]> ").strip()
        if not msg:
            continue
        if msg == "quit":
            sock.sendto(b"__BYE__", client_addr)
            break

        ciphertext = aes_encrypt(aes_key, msg.encode())
        mac        = compute_hmac(hmac_key, ciphertext)
        packet     = pack_message(server_seq, ciphertext, mac)
        sock.sendto(packet, client_addr)
        server_seq += 1

    sock.close()


if __name__ == "__main__":
    main()
