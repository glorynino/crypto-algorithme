"""
app.py — Interface graphique principale TP6 Cryptographie Appliquée
Lancer : python app.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import subprocess
import socket
import sys
import os
import time

# ── Assure que les imports relatifs fonctionnent ──────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from common.crypto_utils import (
    generate_rsa_keypair, serialize_public_key, deserialize_public_key,
    rsa_encrypt, rsa_decrypt, generate_aes_key,
    aes_encrypt, aes_decrypt, compute_hmac, verify_hmac, sha256_hex
)
from common.protocol import send_bytes, recv_bytes

# ══════════════════════════════════════════════════════════════════════════════
#  COULEURS & STYLES
# ══════════════════════════════════════════════════════════════════════════════
BG        = "#0d1117"
BG2       = "#161b22"
BG3       = "#21262d"
ACCENT    = "#c0392b"       # rouge foncé (thème cryptographie)
ACCENT2   = "#e74c3c"
GREEN     = "#2ecc71"
YELLOW    = "#f39c12"
BLUE      = "#3498db"
TEXT      = "#e6edf3"
TEXT2     = "#8b949e"
MONO      = ("Courier New", 10)
TITLE_F   = ("Georgia", 22, "bold")
LABEL_F   = ("Segoe UI", 10)
BTN_F     = ("Segoe UI", 10, "bold")

# ══════════════════════════════════════════════════════════════════════════════
#  WIDGET UTILITAIRES
# ══════════════════════════════════════════════════════════════════════════════

def make_log(parent, height=12) -> scrolledtext.ScrolledText:
    w = scrolledtext.ScrolledText(
        parent, height=height, bg="#0a0e14", fg=TEXT,
        font=MONO, insertbackground=TEXT,
        relief="flat", bd=0, wrap="word",
        selectbackground=ACCENT
    )
    w.tag_config("ok",      foreground=GREEN)
    w.tag_config("err",     foreground=ACCENT2)
    w.tag_config("warn",    foreground=YELLOW)
    w.tag_config("info",    foreground=BLUE)
    w.tag_config("bold",    foreground=TEXT, font=("Courier New", 10, "bold"))
    w.tag_config("dim",     foreground=TEXT2)
    w.config(state="disabled")
    return w


def log(widget, msg, tag=""):
    widget.config(state="normal")
    widget.insert("end", msg + "\n", tag)
    widget.see("end")
    widget.config(state="disabled")


def styled_btn(parent, text, cmd, color=ACCENT, width=20):
    return tk.Button(
        parent, text=text, command=cmd,
        bg=color, fg="white", font=BTN_F,
        relief="flat", bd=0, padx=12, pady=8,
        activebackground=ACCENT2, activeforeground="white",
        cursor="hand2", width=width
    )


def section(parent, title):
    f = tk.LabelFrame(
        parent, text=f"  {title}  ", fg=ACCENT2,
        bg=BG2, font=("Segoe UI", 10, "bold"),
        relief="flat", bd=1, highlightthickness=1,
        highlightbackground=BG3
    )
    return f


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE ACCUEIL
# ══════════════════════════════════════════════════════════════════════════════

class HomePage(tk.Frame):
    def __init__(self, master, switch_cb):
        super().__init__(master, bg=BG)
        self.switch = switch_cb
        self._build()

    def _build(self):
        # En-tête
        hdr = tk.Frame(self, bg=ACCENT, pady=30)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔐 TP 6", font=("Georgia", 36, "bold"),
                 bg=ACCENT, fg="white").pack()
        tk.Label(hdr, text="Sécurisation des Communications",
                 font=("Segoe UI", 14), bg=ACCENT, fg="#ffd0cc").pack()
        tk.Label(hdr, text="Cryptographie Appliquée",
                 font=("Segoe UI", 10), bg=ACCENT, fg="#ffa09a").pack(pady=(0,4))

        # Contexte
        ctx = tk.Frame(self, bg=BG2, pady=14, padx=24)
        ctx.pack(fill="x", padx=20, pady=12)
        tk.Label(ctx, text="Contexte :", font=("Segoe UI", 10, "bold"),
                 bg=BG2, fg=ACCENT2).pack(anchor="w")
        tk.Label(ctx,
                 text="A et B communiquent sur un canal non sécurisé.\n"
                      "Le protocole garantit : confidentialité (AES/RSA), "
                      "authenticité, intégrité et anonymat.",
                 font=LABEL_F, bg=BG2, fg=TEXT2, justify="left",
                 wraplength=680).pack(anchor="w", pady=(4, 0))

        # Cartes des exercices
        cards_frame = tk.Frame(self, bg=BG)
        cards_frame.pack(fill="both", expand=True, padx=20, pady=10)

        exercises = [
            ("6.1", "Sockets TCP/IP",         "🌐", BLUE,
             "Handshake RSA + chiffrement AES\nsur connexion TCP filaire",
             "ex1"),
            ("6.2", "Bluetooth RFCOMM",        "📡", "#9b59b6",
             "Même protocole sur canal\nBluetooth sans fil",
             "ex2"),
            ("6.3", "Wi-Fi / UDP Chat",        "💬", GREEN,
             "Chat bidirectionnel chiffré\navec protection anti-rejeu",
             "ex3"),
            ("6.4", "Vote Homomorphe",         "🗳️", YELLOW,
             "Schéma de Paillier : vote\nsans déchiffrer les bulletins",
             "ex4"),
        ]

        for i, (num, title, icon, color, desc, key) in enumerate(exercises):
            col = i % 2
            row = i // 2
            card = tk.Frame(cards_frame, bg=BG2, pady=18, padx=18,
                            cursor="hand2")
            card.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")
            cards_frame.columnconfigure(col, weight=1)

            top = tk.Frame(card, bg=BG2)
            top.pack(fill="x")
            tk.Label(top, text=icon, font=("Segoe UI", 28),
                     bg=BG2, fg=color).pack(side="left")
            nb_f = tk.Frame(top, bg=color, padx=6, pady=2)
            nb_f.pack(side="left", padx=8)
            tk.Label(nb_f, text=f"Exo {num}", font=("Segoe UI", 9, "bold"),
                     bg=color, fg="white").pack()

            tk.Label(card, text=title, font=("Segoe UI", 13, "bold"),
                     bg=BG2, fg=TEXT).pack(anchor="w", pady=(8, 2))
            tk.Label(card, text=desc, font=("Segoe UI", 9),
                     bg=BG2, fg=TEXT2, justify="left").pack(anchor="w")

            btn = tk.Button(card, text="▶  Ouvrir",
                            bg=color, fg="white", font=BTN_F,
                            relief="flat", bd=0, padx=10, pady=6,
                            activebackground=ACCENT2, cursor="hand2",
                            command=lambda k=key: self.switch(k))
            btn.pack(anchor="w", pady=(10, 0))

        # Libs
        libs = tk.Frame(self, bg=BG3, pady=8, padx=24)
        libs.pack(fill="x", padx=20, pady=(0, 16))
        tk.Label(libs, text="Libs : socket · ssl · cryptography · threading · qrcode · pybluez",
                 font=("Courier New", 9), bg=BG3, fg=TEXT2).pack()


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE EXERCICE 6.1 — TCP/IP
# ══════════════════════════════════════════════════════════════════════════════

class Ex1Page(tk.Frame):
    def __init__(self, master, switch_cb):
        super().__init__(master, bg=BG)
        self.switch   = switch_cb
        self.server_t = None
        self.client_t = None
        self._server_sock  = None
        self._client_sock  = None
        self._aes_key      = None
        self._hmac_key     = None
        self._session_ok   = False
        self._build()

    def _build(self):
        self._header("6.1 — Sécurisation par Sockets TCP/IP", "🌐")

        # Schéma du protocole
        proto = section(self, "Protocole")
        proto.pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(proto,
                 text="  A (client)                      B (serveur)\n"
                      "     │                                 │\n"
                      "     │ ◄──── clé publique RSA ──────── │   Étape 1\n"
                      "     │                                 │\n"
                      "     │ ────── RSA_B(aes_key) ─────────►│   Étape 2\n"
                      "     │ ────── hmac_key ───────────────►│\n"
                      "     │                                 │\n"
                      "     │ ────── AES(msg) + HMAC ────────►│   Étape 3\n"
                      "     │ ◄───── AES(echo) + HMAC ─────── │",
                 font=("Courier New", 9), bg=BG2, fg=BLUE,
                 justify="left").pack(padx=10, pady=6)

        # Deux colonnes : serveur | client
        cols = tk.Frame(self, bg=BG)
        cols.pack(fill="both", expand=True, padx=16, pady=4)

        # ── Serveur ──────────────────────────────────────────────────────────
        srv_f = section(cols, "🖥  Serveur (B)")
        srv_f.pack(side="left", fill="both", expand=True, padx=(0, 6))

        self.log_srv = make_log(srv_f, height=10)
        self.log_srv.pack(fill="both", expand=True, padx=6, pady=6)

        styled_btn(srv_f, "▶  Démarrer serveur",
                   self._start_server, color=BLUE, width=22).pack(pady=(0, 8))

        # ── Client ───────────────────────────────────────────────────────────
        cli_f = section(cols, "💻  Client (A)")
        cli_f.pack(side="left", fill="both", expand=True, padx=(6, 0))

        self.log_cli = make_log(cli_f, height=10)
        self.log_cli.pack(fill="both", expand=True, padx=6, pady=6)

        styled_btn(cli_f, "🔗  Connecter client",
                   self._start_client, color=GREEN, width=22).pack(pady=(0, 4))

        # Zone d'envoi de message
        msg_f = tk.Frame(cli_f, bg=BG2)
        msg_f.pack(fill="x", padx=6, pady=(0, 8))
        self.msg_var = tk.StringVar()
        e = tk.Entry(msg_f, textvariable=self.msg_var,
                     bg=BG3, fg=TEXT, font=MONO,
                     insertbackground=TEXT, relief="flat", bd=4)
        e.pack(side="left", fill="x", expand=True, padx=(0, 6))
        e.bind("<Return>", lambda _: self._send_msg())
        styled_btn(msg_f, "Envoyer ▶", self._send_msg,
                   color=ACCENT, width=10).pack(side="right")

    def _header(self, title, icon):
        h = tk.Frame(self, bg=BG2, pady=12)
        h.pack(fill="x")
        tk.Button(h, text="← Accueil", command=lambda: self.switch("home"),
                  bg=BG3, fg=TEXT2, font=("Segoe UI", 9),
                  relief="flat", bd=0, cursor="hand2").pack(side="left", padx=12)
        tk.Label(h, text=f"{icon}  {title}",
                 font=("Segoe UI", 14, "bold"), bg=BG2, fg=TEXT).pack(side="left")

    # ── Logique serveur ───────────────────────────────────────────────────────
    def _start_server(self):
        if self.server_t and self.server_t.is_alive():
            log(self.log_srv, "[!] Serveur déjà en cours.", "warn"); return
        self.server_t = threading.Thread(target=self._run_server, daemon=True)
        self.server_t.start()

    def _run_server(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 5000))
            srv.listen(1)
            self._server_sock = srv
            log(self.log_srv, "✔  Serveur en écoute sur 127.0.0.1:5000", "ok")

            conn, addr = srv.accept()
            log(self.log_srv, f"✔  Client connecté : {addr}", "ok")

            # Étape 1 : envoyer clé publique RSA
            priv, pub = generate_rsa_keypair()
            send_bytes(conn, serialize_public_key(pub))
            log(self.log_srv, "→  Clé publique RSA envoyée", "info")

            # Étape 2 : recevoir clé AES + HMAC
            enc_aes  = recv_bytes(conn)
            aes_key  = rsa_decrypt(priv, enc_aes)
            hmac_key = recv_bytes(conn)
            log(self.log_srv, f"←  Clé AES reçue (RSA déchiffrée) : {aes_key.hex()[:16]}…", "ok")
            log(self.log_srv, "━━━━  Session sécurisée établie  ━━━━", "bold")

            # Étape 3 : boucle messages
            while True:
                ct  = recv_bytes(conn)
                mac = recv_bytes(conn)
                if not verify_hmac(hmac_key, ct, mac):
                    log(self.log_srv, "⚠  HMAC invalide — message rejeté !", "err"); continue
                pt  = aes_decrypt(aes_key, ct).decode()
                if pt == "__EXIT__":
                    log(self.log_srv, "✔  Client déconnecté proprement.", "ok"); break
                log(self.log_srv, f"◄  Reçu (déchiffré) : {pt}", "ok")
                log(self.log_srv, f"   chiffré           : {ct.hex()[:28]}…", "dim")

                resp = f"Echo ✓ : {pt}".encode()
                enc  = aes_encrypt(aes_key, resp)
                send_bytes(conn, enc)
                send_bytes(conn, compute_hmac(hmac_key, enc))
                log(self.log_srv, f"►  Echo envoyé (chiffré)", "info")

            conn.close(); srv.close()
        except Exception as ex:
            log(self.log_srv, f"[ERR] {ex}", "err")

    # ── Logique client ────────────────────────────────────────────────────────
    def _start_client(self):
        if self._session_ok:
            log(self.log_cli, "[!] Session déjà établie.", "warn"); return
        self.client_t = threading.Thread(target=self._run_client, daemon=True)
        self.client_t.start()

    def _run_client(self):
        try:
            time.sleep(0.3)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", 5000))
            self._client_sock = s
            log(self.log_cli, "✔  Connecté au serveur 127.0.0.1:5000", "ok")

            # Étape 1 : recevoir clé publique
            pub_pem   = recv_bytes(s)
            server_pk = deserialize_public_key(pub_pem)
            log(self.log_cli, "←  Clé publique RSA reçue", "info")

            # Étape 2 : envoyer clé AES chiffrée
            self._aes_key  = generate_aes_key()
            self._hmac_key = generate_aes_key(32)
            send_bytes(s, rsa_encrypt(server_pk, self._aes_key))
            send_bytes(s, self._hmac_key)
            log(self.log_cli, f"→  Clé AES envoyée (chiffrée RSA) : {self._aes_key.hex()[:16]}…", "ok")
            log(self.log_cli, "━━━━  Session sécurisée établie  ━━━━", "bold")
            self._session_ok = True

        except Exception as ex:
            log(self.log_cli, f"[ERR] {ex}", "err")

    def _send_msg(self):
        msg = self.msg_var.get().strip()
        if not msg:
            return
        if not self._session_ok:
            log(self.log_cli, "⚠  Connecte d'abord le client !", "warn"); return
        self.msg_var.set("")

        def _do():
            try:
                ct  = aes_encrypt(self._aes_key, msg.encode())
                mac = compute_hmac(self._hmac_key, ct)
                send_bytes(self._client_sock, ct)
                send_bytes(self._client_sock, mac)
                log(self.log_cli, f"►  Envoyé (clair)    : {msg}", "ok")
                log(self.log_cli, f"   chiffré AES       : {ct.hex()[:28]}…", "dim")

                enc_r = recv_bytes(self._client_sock)
                mac_r = recv_bytes(self._client_sock)
                if verify_hmac(self._hmac_key, enc_r, mac_r):
                    log(self.log_cli, f"◄  Réponse serveur   : {aes_decrypt(self._aes_key, enc_r).decode()}", "info")
            except Exception as ex:
                log(self.log_cli, f"[ERR] {ex}", "err")

        threading.Thread(target=_do, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE EXERCICE 6.3 — UDP Chat
# ══════════════════════════════════════════════════════════════════════════════

class Ex3Page(tk.Frame):
    def __init__(self, master, switch_cb):
        super().__init__(master, bg=BG)
        self.switch     = switch_cb
        self._srv_sock  = None
        self._cli_sock  = None
        self._aes_key   = None
        self._hmac_key  = None
        self._cli_addr  = None
        self._srv_ready = False
        self._cli_ready = False
        self._cli_seq   = 0
        self._srv_seq   = 0
        self._exp_cli   = 0
        self._exp_srv   = 0
        self._build()

    def _build(self):
        self._header("6.3 — Wi-Fi / UDP Chat Sécurisé", "💬")

        info = tk.Frame(self, bg=BG2, pady=8, padx=16)
        info.pack(fill="x")
        tk.Label(info,
                 text="UDP sans connexion → numéro de séquence anti-rejeu intégré  |  "
                      "AES-256-CBC + HMAC-SHA256",
                 font=("Segoe UI", 9), bg=BG2, fg=TEXT2).pack(anchor="w")

        cols = tk.Frame(self, bg=BG)
        cols.pack(fill="both", expand=True, padx=16, pady=8)

        # Serveur
        sf = section(cols, "🖥  Serveur UDP")
        sf.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.log_srv = make_log(sf, height=12)
        self.log_srv.pack(fill="both", expand=True, padx=6, pady=6)

        msg_sf = tk.Frame(sf, bg=BG2)
        msg_sf.pack(fill="x", padx=6, pady=(0, 4))
        self.srv_msg = tk.StringVar()
        e = tk.Entry(msg_sf, textvariable=self.srv_msg,
                     bg=BG3, fg=TEXT, font=MONO,
                     insertbackground=TEXT, relief="flat", bd=4)
        e.pack(side="left", fill="x", expand=True, padx=(0, 6))
        e.bind("<Return>", lambda _: self._srv_send())
        styled_btn(msg_sf, "Envoyer", self._srv_send, color=BLUE, width=8).pack()

        styled_btn(sf, "▶  Démarrer serveur",
                   self._start_server, color=BLUE, width=22).pack(pady=(0, 8))

        # Client
        cf = section(cols, "💻  Client UDP")
        cf.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.log_cli = make_log(cf, height=12)
        self.log_cli.pack(fill="both", expand=True, padx=6, pady=6)

        msg_cf = tk.Frame(cf, bg=BG2)
        msg_cf.pack(fill="x", padx=6, pady=(0, 4))
        self.cli_msg = tk.StringVar()
        e2 = tk.Entry(msg_cf, textvariable=self.cli_msg,
                      bg=BG3, fg=TEXT, font=MONO,
                      insertbackground=TEXT, relief="flat", bd=4)
        e2.pack(side="left", fill="x", expand=True, padx=(0, 6))
        e2.bind("<Return>", lambda _: self._cli_send())
        styled_btn(msg_cf, "Envoyer", self._cli_send, color=GREEN, width=8).pack()

        styled_btn(cf, "🔗  Connecter client",
                   self._start_client, color=GREEN, width=22).pack(pady=(0, 8))

    def _header(self, title, icon):
        h = tk.Frame(self, bg=BG2, pady=12)
        h.pack(fill="x")
        tk.Button(h, text="← Accueil", command=lambda: self.switch("home"),
                  bg=BG3, fg=TEXT2, font=("Segoe UI", 9),
                  relief="flat", bd=0, cursor="hand2").pack(side="left", padx=12)
        tk.Label(h, text=f"{icon}  {title}",
                 font=("Segoe UI", 14, "bold"), bg=BG2, fg=TEXT).pack(side="left")

    import struct

    def _pack(self, seq, ct, mac):
        import struct
        return struct.pack(">II", seq, len(ct)) + ct + mac

    def _unpack(self, data):
        import struct
        seq, ct_len = struct.unpack(">II", data[:8])
        ct  = data[8:8+ct_len]
        mac = data[8+ct_len:]
        return seq, ct, mac

    def _start_server(self):
        def run():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(("127.0.0.1", 5001))
                self._srv_sock = s
                log(self.log_srv, "✔  Serveur UDP en écoute sur :5001", "ok")

                # Handshake
                data, addr = s.recvfrom(65535)
                if data != b"HELLO":
                    log(self.log_srv, "[!] Handshake invalide", "err"); return
                self._cli_addr = addr
                log(self.log_srv, f"✔  Client : {addr}", "ok")

                priv, pub = generate_rsa_keypair()
                s.sendto(serialize_public_key(pub), addr)
                log(self.log_srv, "→  Clé publique RSA envoyée", "info")

                enc_aes, _ = s.recvfrom(65535)
                hmac_raw, _= s.recvfrom(65535)
                self._aes_key  = rsa_decrypt(priv, enc_aes)
                self._hmac_key = hmac_raw
                s.sendto(b"OK", addr)
                log(self.log_srv, f"←  Clé AES reçue : {self._aes_key.hex()[:16]}…", "ok")
                log(self.log_srv, "━━━━  Session UDP sécurisée  ━━━━", "bold")
                self._srv_ready = True

                while True:
                    data, a = s.recvfrom(65535)
                    if data == b"__BYE__":
                        log(self.log_srv, "✔  Client déconnecté.", "ok"); break
                    seq, ct, mac = self._unpack(data)
                    if seq < self._exp_srv:
                        log(self.log_srv, f"⚠  Paquet rejoué détecté (seq={seq}) !", "warn"); continue
                    self._exp_srv = seq + 1
                    if not verify_hmac(self._hmac_key, ct, mac):
                        log(self.log_srv, "⚠  HMAC invalide !", "err"); continue
                    msg = aes_decrypt(self._aes_key, ct).decode()
                    log(self.log_srv, f"◄  [{seq}] {msg}", "ok")
                    log(self.log_srv, f"   chiffré : {ct.hex()[:24]}…", "dim")
            except Exception as ex:
                log(self.log_srv, f"[ERR] {ex}", "err")

        threading.Thread(target=run, daemon=True).start()

    def _start_client(self):
        def run():
            try:
                time.sleep(0.4)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._cli_sock = s
                srv = ("127.0.0.1", 5001)

                s.sendto(b"HELLO", srv)
                pub_pem, _ = s.recvfrom(65535)
                pk = deserialize_public_key(pub_pem)
                log(self.log_cli, "←  Clé publique RSA reçue", "info")

                self._aes_key  = generate_aes_key()
                self._hmac_key = generate_aes_key(32)
                s.sendto(rsa_encrypt(pk, self._aes_key), srv)
                s.sendto(self._hmac_key, srv)

                ack, _ = s.recvfrom(65535)
                if ack == b"OK":
                    log(self.log_cli, f"→  Clé AES envoyée : {self._aes_key.hex()[:16]}…", "ok")
                    log(self.log_cli, "━━━━  Session UDP sécurisée  ━━━━", "bold")
                    self._cli_ready = True

                while True:
                    data, _ = s.recvfrom(65535)
                    if data == b"__BYE__": break
                    seq, ct, mac = self._unpack(data)
                    if not verify_hmac(self._hmac_key, ct, mac):
                        log(self.log_cli, "⚠  HMAC invalide !", "err"); continue
                    msg = aes_decrypt(self._aes_key, ct).decode()
                    log(self.log_cli, f"◄  [{seq}] {msg}", "ok")
            except Exception as ex:
                log(self.log_cli, f"[ERR] {ex}", "err")

        threading.Thread(target=run, daemon=True).start()

    def _cli_send(self):
        msg = self.cli_msg.get().strip()
        if not msg or not self._cli_ready: return
        self.cli_msg.set("")
        ct  = aes_encrypt(self._aes_key, msg.encode())
        mac = compute_hmac(self._hmac_key, ct)
        pkt = self._pack(self._cli_seq, ct, mac)
        self._cli_sock.sendto(pkt, ("127.0.0.1", 5001))
        log(self.log_cli, f"►  [{self._cli_seq}] {msg}", "info")
        self._cli_seq += 1

    def _srv_send(self):
        msg = self.srv_msg.get().strip()
        if not msg or not self._srv_ready or not self._cli_addr: return
        self.srv_msg.set("")
        ct  = aes_encrypt(self._aes_key, msg.encode())
        mac = compute_hmac(self._hmac_key, ct)
        pkt = self._pack(self._srv_seq, ct, mac)
        self._srv_sock.sendto(pkt, self._cli_addr)
        log(self.log_srv, f"►  [{self._srv_seq}] {msg}", "info")
        self._srv_seq += 1


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE EXERCICE 6.2 — BLUETOOTH (info + simulation)
# ══════════════════════════════════════════════════════════════════════════════

class Ex2Page(tk.Frame):
    def __init__(self, master, switch_cb):
        super().__init__(master, bg=BG)
        self.switch = switch_cb
        self._build()

    def _build(self):
        h = tk.Frame(self, bg=BG2, pady=12)
        h.pack(fill="x")
        tk.Button(h, text="← Accueil", command=lambda: self.switch("home"),
                  bg=BG3, fg=TEXT2, font=("Segoe UI", 9),
                  relief="flat", bd=0, cursor="hand2").pack(side="left", padx=12)
        tk.Label(h, text="📡  6.2 — Sécurisation Bluetooth RFCOMM",
                 font=("Segoe UI", 14, "bold"), bg=BG2, fg=TEXT).pack(side="left")

        # Infos & prérequis
        info_f = section(self, "Prérequis matériels")
        info_f.pack(fill="x", padx=16, pady=10)
        tk.Label(info_f,
                 text="Ce protocole nécessite deux machines physiques avec Bluetooth activé.\n"
                      "Le code est prêt dans ex2_bluetooth/server.py et ex2_bluetooth/client.py",
                 font=LABEL_F, bg=BG2, fg=TEXT2).pack(padx=10, pady=6, anchor="w")

        # Protocole
        proto_f = section(self, "Protocole RFCOMM (identique à TCP)")
        proto_f.pack(fill="x", padx=16, pady=6)
        tk.Label(proto_f,
                 text="  Machine B (serveur)                Machine A (client)\n"
                      "         │                                  │\n"
                      "         │ ◄── bluetooth.find_service() ─── │  Découverte UUID\n"
                      "         │ ◄── connexion RFCOMM ─────────── │\n"
                      "         │ ────── clé publique RSA ────────► │\n"
                      "         │ ◄───── RSA_B(aes_key) ─────────── │\n"
                      "         │ ◄───── hmac_key ────────────────── │\n"
                      "         │                                  │\n"
                      "         │ ◄──── AES(msg) + HMAC ─────────── │  Messages",
                 font=("Courier New", 9), bg=BG2, fg="#9b59b6",
                 justify="left").pack(padx=10, pady=6)

        # Instructions
        cmd_f = section(self, "Commandes de lancement")
        cmd_f.pack(fill="x", padx=16, pady=6)
        cmds = [
            ("Machine B (serveur) :", "python ex2_bluetooth/server.py"),
            ("Machine A (client)  :", "python ex2_bluetooth/client.py"),
            ("Installation lib    :", "pip install pybluez"),
            ("Linux uniquement    :", "sudo apt install libbluetooth-dev"),
        ]
        for label, cmd in cmds:
            row = tk.Frame(cmd_f, bg=BG2)
            row.pack(fill="x", padx=10, pady=2)
            tk.Label(row, text=label, font=("Segoe UI", 9), bg=BG2, fg=TEXT2, width=22, anchor="w").pack(side="left")
            tk.Label(row, text=cmd, font=("Courier New", 10), bg=BG3, fg=GREEN, padx=8, pady=2).pack(side="left")

        # Simulation locale
        sim_f = section(self, "Simulation locale (sans Bluetooth)")
        sim_f.pack(fill="both", expand=True, padx=16, pady=6)
        self.log = make_log(sim_f, height=8)
        self.log.pack(fill="both", expand=True, padx=6, pady=6)
        styled_btn(sim_f, "▶  Simuler l'échange RFCOMM",
                   self._simulate, color="#9b59b6", width=28).pack(pady=(0, 8))

    def _simulate(self):
        log(self.log, "━━━━  Simulation Bluetooth RFCOMM  ━━━━", "bold")
        steps = [
            ("info",  "Serveur B : génération paire de clés RSA-2048…"),
            ("ok",    "Serveur B : clé publique RSA prête."),
            ("info",  "Client A  : connexion RFCOMM établie."),
            ("info",  "Client A  : réception clé publique RSA du serveur."),
            ("ok",    "Client A  : génération clé AES-256 aléatoire."),
            ("info",  "Client A  : chiffrement AES avec RSA_B → envoi."),
            ("ok",    "Serveur B : déchiffrement RSA → clé AES obtenue."),
            ("bold",  "Session sécurisée Bluetooth établie ✓"),
            ("ok",    'Client A  → "Bonjour depuis le Bluetooth !" (chiffré AES)'),
            ("dim",   "           chiffré : a3f92bc1e047d8… (tronqué)"),
            ("ok",    "Serveur B ← déchiffré : Bonjour depuis le Bluetooth !"),
            ("info",  "Serveur B → Echo BT-Echo: Bonjour… (chiffré AES)"),
            ("ok",    "Client A  ← Echo reçu et vérifié (HMAC ✓)"),
        ]

        def run():
            for tag, msg in steps:
                self.after(0, lambda t=tag, m=msg: log(self.log, m, t))
                time.sleep(0.6)
        threading.Thread(target=run, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════════════
#  PAGE EXERCICE 6.4 — VOTE HOMOMORPHE
# ══════════════════════════════════════════════════════════════════════════════

class Ex4Page(tk.Frame):
    def __init__(self, master, switch_cb):
        super().__init__(master, bg=BG)
        self.switch = switch_cb
        self._pub = None
        self._prv = None
        self._votes: list = []
        self._voter_names: list = []
        self._build()

    def _build(self):
        h = tk.Frame(self, bg=BG2, pady=12)
        h.pack(fill="x")
        tk.Button(h, text="← Accueil", command=lambda: self.switch("home"),
                  bg=BG3, fg=TEXT2, font=("Segoe UI", 9),
                  relief="flat", bd=0, cursor="hand2").pack(side="left", padx=12)
        tk.Label(h, text="🗳️  6.4 — Vote Électronique Homomorphe (Paillier)",
                 font=("Segoe UI", 14, "bold"), bg=BG2, fg=TEXT).pack(side="left")

        # Explication
        exp_f = section(self, "Principe de Paillier")
        exp_f.pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(exp_f,
                 text="  Enc(a) · Enc(b) mod n²  =  Enc(a + b)\n"
                      "  → Les votes sont additionnés SANS être déchiffrés individuellement → anonymat garanti",
                 font=("Courier New", 9), bg=BG2, fg=YELLOW,
                 justify="left").pack(padx=10, pady=6)

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=16, pady=4)

        # ── Panneau gauche : contrôles ────────────────────────────────────────
        left = tk.Frame(body, bg=BG, width=260)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)

        # Génération clés
        key_f = section(left, "1. Autorité — Clés")
        key_f.pack(fill="x", pady=(0, 6))
        styled_btn(key_f, "🔑  Générer clés Paillier",
                   self._gen_keys, color=ACCENT, width=24).pack(pady=8)
        self.key_lbl = tk.Label(key_f, text="(pas encore générées)",
                                 font=("Courier New", 8), bg=BG2, fg=TEXT2,
                                 wraplength=230, justify="left")
        self.key_lbl.pack(padx=8, pady=(0, 6))

        # Ajouter un vote
        vote_f = section(left, "2. Votant — Déposer un bulletin")
        vote_f.pack(fill="x", pady=(0, 6))

        tk.Label(vote_f, text="Nom du votant :", font=LABEL_F,
                 bg=BG2, fg=TEXT2).pack(padx=8, pady=(6, 0), anchor="w")
        self.name_var = tk.StringVar(value="Alice")
        tk.Entry(vote_f, textvariable=self.name_var,
                 bg=BG3, fg=TEXT, font=MONO,
                 insertbackground=TEXT, relief="flat", bd=4).pack(
                     fill="x", padx=8, pady=4)

        tk.Label(vote_f, text="Vote :", font=LABEL_F,
                 bg=BG2, fg=TEXT2).pack(padx=8, anchor="w")
        self.vote_var = tk.IntVar(value=1)
        brow = tk.Frame(vote_f, bg=BG2)
        brow.pack(fill="x", padx=8, pady=4)
        tk.Radiobutton(brow, text="✅  OUI  (1)", variable=self.vote_var, value=1,
                       bg=BG2, fg=GREEN, selectcolor=BG3,
                       activebackground=BG2, font=LABEL_F).pack(side="left", padx=4)
        tk.Radiobutton(brow, text="❌  NON  (0)", variable=self.vote_var, value=0,
                       bg=BG2, fg=ACCENT2, selectcolor=BG3,
                       activebackground=BG2, font=LABEL_F).pack(side="left", padx=4)

        styled_btn(vote_f, "🗳  Voter",
                   self._cast_vote, color=GREEN, width=24).pack(pady=8)

        # Décompte
        tally_f = section(left, "3. Autorité — Décompte")
        tally_f.pack(fill="x", pady=(0, 6))
        styled_btn(tally_f, "📊  Décompter les votes",
                   self._tally, color=YELLOW, width=24).pack(pady=8)

        self.result_lbl = tk.Label(tally_f, text="",
                                    font=("Segoe UI", 13, "bold"),
                                    bg=BG2, fg=YELLOW)
        self.result_lbl.pack(pady=(0, 8))

        # ── Panneau droit : journal ───────────────────────────────────────────
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        log_f = section(right, "Journal de vote")
        log_f.pack(fill="both", expand=True)
        self.log = make_log(log_f, height=18)
        self.log.pack(fill="both", expand=True, padx=6, pady=6)

        styled_btn(log_f, "🗑  Réinitialiser",
                   self._reset, color=BG3, width=18).pack(pady=(0, 6))

    # ── Paillier inline (évite import circulaire) ─────────────────────────────
    @staticmethod
    def _gen_prime(bits):
        import random, math
        def is_prime(n, k=12):
            if n < 2: return False
            if n in (2, 3): return True
            if n % 2 == 0: return False
            r, d = 0, n - 1
            while d % 2 == 0: r += 1; d //= 2
            for _ in range(k):
                a = random.randrange(2, n - 1)
                x = pow(a, d, n)
                if x in (1, n - 1): continue
                for _ in range(r - 1):
                    x = pow(x, 2, n); 
                    if x == n - 1: break
                else: return False
            return True
        while True:
            p = random.getrandbits(bits) | (1 << bits - 1) | 1
            if is_prime(p): return p

    def _gen_keys(self):
        def run():
            log(self.log, "Génération des clés Paillier (512 bits)…", "info")
            import math
            bits = 512
            p = self._gen_prime(bits // 2)
            q = self._gen_prime(bits // 2)
            while p == q: q = self._gen_prime(bits // 2)
            n   = p * q
            lam = (p-1)*(q-1) // math.gcd(p-1, q-1)
            g   = n + 1
            mu  = pow((pow(g, lam, n*n) - 1) // n, -1, n)
            self._pub = {"n": n, "g": g, "n2": n*n}
            self._prv = {"lam": lam, "mu": mu}
            self._votes = []
            self._voter_names = []
            n_str = str(n)
            log(self.log, f"✔  Clé publique  n = {n_str[:20]}…{n_str[-6:]}", "ok")
            log(self.log, f"✔  g = n + 1 (choix standard)", "ok")
            log(self.log, "━━━━  Clés prêtes  ━━━━", "bold")
            self.after(0, lambda: self.key_lbl.config(
                text=f"n = {n_str[:18]}…\n(512 bits)"))
        threading.Thread(target=run, daemon=True).start()

    def _cast_vote(self):
        if not self._pub:
            messagebox.showwarning("Attention", "Génère d'abord les clés !"); return
        name   = self.name_var.get().strip() or "Votant"
        choice = self.vote_var.get()

        def run():
            import random, math
            n, g, n2 = self._pub["n"], self._pub["g"], self._pub["n2"]
            while True:
                r = random.randrange(1, n)
                if math.gcd(r, n) == 1: break
            enc = pow(g, choice, n2) * pow(r, n, n2) % n2
            self._votes.append(enc)
            self._voter_names.append(name)

            receipt = sha256_hex(str(enc).encode())
            log(self.log, f"✔  {name} vote : {'OUI ✅' if choice else 'NON ❌'}", "ok")
            log(self.log, f"   Chiffré Paillier : {str(enc)[:30]}…", "dim")
            log(self.log, f"   Reçu SHA-256     : {receipt[:16]}…", "info")
            log(self.log, f"   Total bulletins  : {len(self._votes)}", "bold")

        threading.Thread(target=run, daemon=True).start()

    def _tally(self):
        if not self._votes:
            messagebox.showwarning("Attention", "Aucun vote enregistré !"); return

        def run():
            log(self.log, "━━━━  Décompte homomorphique  ━━━━", "bold")
            n2   = self._pub["n2"]
            n    = self._pub["n"]
            lam  = self._prv["lam"]
            mu   = self._prv["mu"]

            total_enc = self._votes[0]
            for i, ev in enumerate(self._votes[1:], 1):
                total_enc = total_enc * ev % n2
                log(self.log, f"   Enc(total) après {i+1} votes : {str(total_enc)[:20]}…", "dim")

            log(self.log, f"   Enc(total) final : {str(total_enc)[:30]}…", "info")

            # Déchiffrement
            x      = pow(total_enc, lam, n2)
            l_val  = (x - 1) // n
            result = l_val * mu % n

            oui = result
            non = len(self._votes) - oui
            log(self.log, f"✔  Résultat déchiffré : {result}", "ok")
            log(self.log, f"   OUI : {oui}  /  NON : {non}  /  Total : {len(self._votes)}", "bold")
            self.after(0, lambda: self.result_lbl.config(
                text=f"OUI : {oui}  |  NON : {non}"))

        threading.Thread(target=run, daemon=True).start()

    def _reset(self):
        self._pub = None; self._prv = None
        self._votes = []; self._voter_names = []
        self.result_lbl.config(text="")
        self.key_lbl.config(text="(pas encore générées)")
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")
        log(self.log, "Réinitialisé.", "info")


# ══════════════════════════════════════════════════════════════════════════════
#  APPLICATION PRINCIPALE
# ══════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TP6 — Cryptographie Appliquée")
        self.geometry("900x680")
        self.minsize(800, 600)
        self.configure(bg=BG)
        self._pages = {}
        self._current = None
        self._build_nav()
        self._show("home")

    def _build_nav(self):
        self._pages["home"] = HomePage(self, self._show)
        self._pages["ex1"]  = Ex1Page(self, self._show)
        self._pages["ex2"]  = Ex2Page(self, self._show)
        self._pages["ex3"]  = Ex3Page(self, self._show)
        self._pages["ex4"]  = Ex4Page(self, self._show)
        for p in self._pages.values():
            p.place(relx=0, rely=0, relwidth=1, relheight=1)

    def _show(self, key: str):
        if self._current:
            self._current.lower()
        self._pages[key].lift()
        self._current = self._pages[key]


if __name__ == "__main__":
    app = App()
    app.mainloop()