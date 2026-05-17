"""
common/protocol.py
Utilitaires de protocole réseau : envoi/réception de messages encadrés.
Format d'un message : [4 bytes longueur big-endian] + [données]
"""

import struct
import socket
import json


def send_bytes(sock: socket.socket, data: bytes) -> None:
    """Envoie des bytes avec un en-tête de longueur (4 bytes)."""
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_bytes(sock: socket.socket) -> bytes:
    """Reçoit des bytes préfixés par un en-tête de longueur."""
    raw_len = _recv_exact(sock, 4)
    msg_len = struct.unpack(">I", raw_len)[0]
    return _recv_exact(sock, msg_len)


def send_json(sock: socket.socket, obj: dict) -> None:
    """Sérialise un dict en JSON et l'envoie."""
    send_bytes(sock, json.dumps(obj).encode())


def recv_json(sock: socket.socket) -> dict:
    """Reçoit et désérialise un message JSON."""
    return json.loads(recv_bytes(sock).decode())


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Lit exactement n bytes depuis le socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connexion fermée prématurément.")
        buf += chunk
    return buf
