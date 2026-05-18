"""Portable project paths for TP scripts (Windows/Linux)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

TP1_SUBDIRS = ("Caesar cipher", "Vignere cipher", "HILL", "OTP algorithm")
TP2_SUBDIRS = ("RC4", "DES", "AES")
TP3_SUBDIRS = ("DH", "RSA", "ElGamal", "ECC")


def add_to_path(*relative_dirs: str) -> Path:
    """Insert project root and subdirs at the front of sys.path."""
    paths = [ROOT, *[ROOT / d for d in relative_dirs]]
    for p in reversed(paths):
        s = str(p)
        if s not in sys.path:
            sys.path.insert(0, s)
    return ROOT


def setup_tp1_paths() -> Path:
    return add_to_path(*TP1_SUBDIRS)


def setup_tp2_paths() -> Path:
    return add_to_path(*TP2_SUBDIRS)


def setup_tp3_paths() -> Path:
    return add_to_path(*TP3_SUBDIRS)


def setup_project_root() -> Path:
    return add_to_path()
