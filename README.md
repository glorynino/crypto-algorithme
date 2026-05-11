# Cryptography Exercises

This workspace contains a set of educational Python implementations for classical, symmetric, and network-oriented cryptography exercises.

The goal of the codebase is clarity and correctness for coursework, not production hardening.

## What is implemented

- Classical ciphers: Caesar, Vigenere, Affine, Playfair, Hill, OTP, RC4
- Symmetric cryptography: DES, CBC helper, AES-128
- Secure terminal communication: TCP chat with RSA-OAEP key exchange and AES-GCM message protection

## Project layout

- [AES/](AES/) - Pure Python AES-128 implementation and CLI
- [AFFINE/](AFFINE/) - Affine cipher demo
- [Caesar cipher/](Caesar%20cipher/) - Caesar cipher and tests
- [CBC/](CBC/) - DES-CBC helper built with PyCryptodome
- [DES/](DES/) - DES and 3DES helpers built with PyCryptodome
- [HILL/](HILL/) - Hill cipher implementation and known-plaintext key recovery
- [OTP algorithm/](OTP%20algorithm/) - One-time pad helpers
- [RC4/](RC4/) - RC4 stream cipher helpers
- [Vignere cipher/](Vignere%20cipher/) - Vigenere cipher and tests
- [playfair algorithm/](playfair%20algorithm/) - Playfair cipher implementation
- [secure_comm/](secure_comm/) - Terminal secure chat demo

## Dependencies

Install the Python packages listed in [requirements.txt](requirements.txt).

Recommended command:

```bash
/home/matt-anis/Studies/Crypto/.venv/bin/pip install -r requirements.txt
```

## Running the modules

### AES-128

Run the CLI:

```bash
cd AES
/home/matt-anis/Studies/Crypto/.venv/bin/python main.py
```

Run tests:

```bash
cd AES
/home/matt-anis/Studies/Crypto/.venv/bin/python tests.py
```

### Caesar

```bash
cd "Caesar cipher"
/home/matt-anis/Studies/Crypto/.venv/bin/python tests.py
```

### Vigenere

```bash
cd "Vignere cipher"
/home/matt-anis/Studies/Crypto/.venv/bin/python tests.py
```

### Hill

```bash
cd HILL
/home/matt-anis/Studies/Crypto/.venv/bin/python hill.py
```

### OTP

```bash
cd "OTP algorithm"
/home/matt-anis/Studies/Crypto/.venv/bin/python tests.py
```

### RC4

```bash
cd RC4
/home/matt-anis/Studies/Crypto/.venv/bin/python tests.py
```

### DES and CBC

```bash
cd DES
/home/matt-anis/Studies/Crypto/.venv/bin/python des.py
```

```bash
cd CBC
/home/matt-anis/Studies/Crypto/.venv/bin/python cbc.py
```

### Secure chat over TCP

Start the server on machine A:

```bash
cd secure_comm
/home/matt-anis/Studies/Crypto/.venv/bin/python server.py --host 0.0.0.0 --port 9000
```

Copy `server_public.pem` from machine A to machine B, then start the client:

```bash
cd secure_comm
/home/matt-anis/Studies/Crypto/.venv/bin/python client.py --host <server-ip> --port 9000 --server-public-key server_public.pem
```

Type messages in either terminal. Use `/quit` to close the session.

## Notes on correctness and scope

- AES uses a custom pure Python implementation with PKCS#7 padding.
- Hill now validates matrix invertibility modulo 26 and supports known-plaintext key recovery.
- OTP, RC4, DES, and CBC are now byte-oriented and reusable instead of being demo-only scripts.
- The secure chat demo uses RSA-OAEP to protect a random AES session key, then AES-GCM for authenticated encryption of the chat frames.

## Security limitations

These implementations are for coursework and demonstrations.

- ECB mode is still insecure for real messages.
- RC4 is deprecated and should not be used in real systems.
- DES is obsolete and only kept for educational reasons.
- The chat demo trusts the server public key file; if that key is replaced, the connection is vulnerable to impersonation.

## Validation

The codebase should be validated by running the local test scripts in each folder and by trying a loopback chat session between the secure chat client and server.
