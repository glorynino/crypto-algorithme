"""
ex2_bluetooth/client.py  —  Exercice 6.2 : Sécurisation Bluetooth (RFCOMM)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.crypto_utils import (
    generate_aes_key, deserialize_public_key,
    rsa_encrypt, aes_encrypt, aes_decrypt,
    compute_hmac, verify_hmac
)
from common.protocol import send_bytes, recv_bytes

try:
    import bluetooth
except ImportError:
    raise ImportError("Installez pybluez : pip install pybluez")

SERVICE_UUID = "94f39d29-7d6d-437d-973b-fba39e49d4ee"


def find_server():
    """Recherche le service sur les appareils Bluetooth à portée."""
    print("[*] Recherche du service Bluetooth…")
    services = bluetooth.find_service(uuid=SERVICE_UUID)
    if not services:
        raise RuntimeError("Service introuvable. Le serveur est-il lancé ?")
    svc = services[0]
    print(f"[+] Service trouvé : {svc['host']}:{svc['port']}")
    return svc["host"], svc["port"]


def main():
    host, port = find_server()

    sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    sock.connect((host, port))
    print(f"[+] Connecté à {host} canal {port}")

    # Étape 1 – clé publique RSA
    pub_pem   = recv_bytes(sock)
    server_pk = deserialize_public_key(pub_pem)

    # Étape 2 – envoyer clé AES + HMAC
    aes_key  = generate_aes_key()
    hmac_key = generate_aes_key(32)
    send_bytes(sock, rsa_encrypt(server_pk, aes_key))
    send_bytes(sock, hmac_key)
    print("[*] Session sécurisée Bluetooth établie.\n")

    # Étape 3 – messages
    while True:
        msg = input("[BT]> ").strip()
        if not msg:
            continue

        payload    = msg.encode() if msg != "quit" else b"__EXIT__"
        ciphertext = aes_encrypt(aes_key, payload)
        mac        = compute_hmac(hmac_key, ciphertext)
        send_bytes(sock, ciphertext)
        send_bytes(sock, mac)

        if msg == "quit":
            break

        enc_resp = recv_bytes(sock)
        mac_resp = recv_bytes(sock)
        if verify_hmac(hmac_key, enc_resp, mac_resp):
            print(f"[Serveur BT] {aes_decrypt(aes_key, enc_resp).decode()}")
        else:
            print("[!] Réponse invalide.")

    sock.close()


if __name__ == "__main__":
    main()
