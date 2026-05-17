"""
ex2_bluetooth/server.py  —  Exercice 6.2 : Sécurisation Bluetooth (RFCOMM)
===========================================================================
Même protocole cryptographique que TCP, mais sur socket Bluetooth RFCOMM.
Nécessite : pybluez  (pip install pybluez)
            Un adaptateur Bluetooth actif.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.crypto_utils import (
    generate_rsa_keypair, serialize_public_key,
    rsa_decrypt, aes_decrypt, verify_hmac, aes_encrypt, compute_hmac
)
from common.protocol import send_bytes, recv_bytes

try:
    import bluetooth
except ImportError:
    raise ImportError("Installez pybluez : pip install pybluez")

# UUID de service dédié à ce TP
SERVICE_UUID = "94f39d29-7d6d-437d-973b-fba39e49d4ee"
PORT = bluetooth.PORT_ANY


def handle_client(client_sock, client_info):
    print(f"[+] Connexion Bluetooth de {client_info}")

    # Étape 1 – envoyer clé publique RSA
    private_key, public_key = generate_rsa_keypair()
    send_bytes(client_sock, serialize_public_key(public_key))

    # Étape 2 – recevoir clé AES + clé HMAC
    encrypted_aes_key = recv_bytes(client_sock)
    aes_key  = rsa_decrypt(private_key, encrypted_aes_key)
    hmac_key = recv_bytes(client_sock)
    print("[*] Session sécurisée Bluetooth établie.")

    # Étape 3 – boucle messages
    while True:
        try:
            ciphertext = recv_bytes(client_sock)
            mac        = recv_bytes(client_sock)

            if not verify_hmac(hmac_key, ciphertext, mac):
                print("[!] HMAC invalide.")
                continue

            plaintext = aes_decrypt(aes_key, ciphertext)
            message   = plaintext.decode()
            if message == "__EXIT__":
                print("[*] Client déconnecté.")
                break
            print(f"[Client BT] {message}")

            response  = f"BT-Echo: {message}".encode()
            enc_resp  = aes_encrypt(aes_key, response)
            mac_resp  = compute_hmac(hmac_key, enc_resp)
            send_bytes(client_sock, enc_resp)
            send_bytes(client_sock, mac_resp)

        except Exception as e:
            print(f"[!] Erreur : {e}")
            break

    client_sock.close()


def main():
    server_sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    server_sock.bind(("", PORT))
    server_sock.listen(1)
    actual_port = server_sock.getsockname()[1]

    bluetooth.advertise_service(
        server_sock,
        "SecureCryptoTP6",
        service_id=SERVICE_UUID,
        service_classes=[SERVICE_UUID, bluetooth.SERIAL_PORT_CLASS],
        profiles=[bluetooth.SERIAL_PORT_PROFILE]
    )

    print(f"[Serveur BT] En écoute sur le canal RFCOMM {actual_port}")
    print(f"[Serveur BT] UUID : {SERVICE_UUID}")

    client_sock, client_info = server_sock.accept()
    handle_client(client_sock, client_info)
    server_sock.close()


if __name__ == "__main__":
    main()
