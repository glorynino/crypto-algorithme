"""
ex3_udp_chat/client.py  —  Exercice 6.3 : Sécurisation sur Wi-Fi / UDP
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import socket
import struct
import threading
from common.crypto_utils import (
    generate_aes_key, deserialize_public_key,
    rsa_encrypt, aes_encrypt, aes_decrypt,
    compute_hmac, verify_hmac
)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5001
MAX_DGRAM   = 65535


def pack_message(seq: int, ciphertext: bytes, mac: bytes) -> bytes:
    return struct.pack(">II", seq, len(ciphertext)) + ciphertext + mac


def unpack_message(data: bytes):
    seq, ct_len = struct.unpack(">II", data[:8])
    ciphertext  = data[8 : 8 + ct_len]
    mac         = data[8 + ct_len :]
    return seq, ciphertext, mac


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server = (SERVER_HOST, SERVER_PORT)

    # ── Handshake ──────────────────────────────────────────────────────────
    sock.sendto(b"HELLO", server)

    pub_pem, _ = sock.recvfrom(MAX_DGRAM)
    server_pk  = deserialize_public_key(pub_pem)

    aes_key  = generate_aes_key()
    hmac_key = generate_aes_key(32)
    sock.sendto(rsa_encrypt(server_pk, aes_key), server)
    sock.sendto(hmac_key, server)

    ack, _ = sock.recvfrom(MAX_DGRAM)
    if ack != b"OK":
        print("[!] Handshake échoué.")
        return
    print(f"[+] Session UDP sécurisée établie avec {SERVER_HOST}:{SERVER_PORT}\n")

    # ── Boucle chat ────────────────────────────────────────────────────────
    expected_seq = 0
    client_seq   = 0

    def receive_loop():
        nonlocal expected_seq
        while True:
            data, _ = sock.recvfrom(MAX_DGRAM)
            if data == b"__BYE__":
                print("\n[*] Serveur déconnecté.")
                return

            seq, ciphertext, mac = unpack_message(data)
            if seq < expected_seq:
                print(f"[!] Paquet rejoué (seq={seq})")
                continue
            expected_seq = seq + 1

            if not verify_hmac(hmac_key, ciphertext, mac):
                print(f"[!] HMAC invalide (seq={seq})")
                continue

            msg = aes_decrypt(aes_key, ciphertext).decode()
            print(f"\r[Serveur] {msg}\n[Vous]> ", end="", flush=True)

    t = threading.Thread(target=receive_loop, daemon=True)
    t.start()

    while True:
        msg = input("[Vous]> ").strip()
        if not msg:
            continue
        if msg == "quit":
            sock.sendto(b"__BYE__", server)
            break

        ciphertext = aes_encrypt(aes_key, msg.encode())
        mac        = compute_hmac(hmac_key, ciphertext)
        packet     = pack_message(client_seq, ciphertext, mac)
        sock.sendto(packet, server)
        client_seq += 1

    sock.close()


if __name__ == "__main__":
    main()
