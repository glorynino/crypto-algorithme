"""Terminal-based secure chat client."""

from __future__ import annotations

import argparse
import os
import socket
import struct
import threading
from pathlib import Path

try:
    from .crypto import load_public_key, pack_frame, rsa_encrypt, sha256_fingerprint, unpack_frame
except ImportError:
    from crypto import load_public_key, pack_frame, rsa_encrypt, sha256_fingerprint, unpack_frame


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        chunks.extend(chunk)
    return bytes(chunks)


def _recv_frame(connection: socket.socket) -> bytes:
    (size,) = struct.unpack("!I", _recv_exact(connection, 4))
    return _recv_exact(connection, size)


def _send_frame(connection: socket.socket, payload: bytes) -> None:
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def chat(host: str, port: int, server_public_key_path: Path):
    server_public_key = load_public_key(server_public_key_path)
    print(f"Server fingerprint: {sha256_fingerprint(server_public_key)}")

    session_key = os.urandom(32)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.connect((host, port))
        _send_frame(connection, rsa_encrypt(server_public_key, session_key))
        ack = unpack_frame(session_key, _recv_frame(connection))
        print(ack)

        def receiver_loop():
            while True:
                try:
                    frame = _recv_frame(connection)
                    message = unpack_frame(session_key, frame)
                except Exception:
                    print("Server disconnected.")
                    break
                print(f"Server: {message}")

        threading.Thread(target=receiver_loop, daemon=True).start()

        while True:
            message = input("You> ")
            if message.strip().lower() in {"/quit", "quit", "exit"}:
                break
            _send_frame(connection, pack_frame(session_key, message))


def main():
    parser = argparse.ArgumentParser(description="Terminal secure chat client")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--server-public-key", default="server_public.pem")
    args = parser.parse_args()

    chat(args.host, args.port, Path(args.server_public_key))


if __name__ == "__main__":
    main()
