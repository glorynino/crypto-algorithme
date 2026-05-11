"""Terminal-based secure chat server."""

from __future__ import annotations

import argparse
import socket
import struct
import threading
from pathlib import Path

try:
    from .crypto import (
        generate_rsa_keypair,
        load_private_key,
        pack_frame,
        rsa_decrypt,
        save_private_key,
        save_public_key,
        sha256_fingerprint,
        unpack_frame,
    )
except ImportError:
    from crypto import (
        generate_rsa_keypair,
        load_private_key,
        pack_frame,
        rsa_decrypt,
        save_private_key,
        save_public_key,
        sha256_fingerprint,
        unpack_frame,
    )


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


def ensure_keys(private_key_path: Path, public_key_path: Path):
    if private_key_path.exists() and public_key_path.exists():
        private_key = load_private_key(private_key_path)
        return private_key, private_key.public_key()

    private_key, public_key = generate_rsa_keypair()
    save_private_key(private_key, private_key_path)
    save_public_key(public_key, public_key_path)
    return private_key, public_key


def serve(host: str, port: int, private_key_path: Path, public_key_path: Path):
    private_key, public_key = ensure_keys(private_key_path, public_key_path)
    print(f"Server public key fingerprint: {sha256_fingerprint(public_key)}")
    print(f"Listening on {host}:{port}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        connection, address = listener.accept()

        with connection:
            print(f"Client connected from {address[0]}:{address[1]}")
            encrypted_session_key = _recv_frame(connection)
            session_key = rsa_decrypt(private_key, encrypted_session_key)
            _send_frame(connection, pack_frame(session_key, "session established"))

            def receiver_loop():
                while True:
                    try:
                        frame = _recv_frame(connection)
                        message = unpack_frame(session_key, frame)
                    except Exception:
                        print("Client disconnected.")
                        break
                    print(f"Client: {message}")

            threading.Thread(target=receiver_loop, daemon=True).start()

            while True:
                message = input("You> ")
                if message.strip().lower() in {"/quit", "quit", "exit"}:
                    break
                _send_frame(connection, pack_frame(session_key, message))


def main():
    parser = argparse.ArgumentParser(description="Terminal secure chat server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--private-key", default="server_private.pem")
    parser.add_argument("--public-key", default="server_public.pem")
    args = parser.parse_args()

    serve(args.host, args.port, Path(args.private_key), Path(args.public_key))


if __name__ == "__main__":
    main()
