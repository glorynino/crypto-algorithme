"""
Console colorée pour les scripts TP (Windows + Linux).
Exercice = cyan | Attaque = rouge | Données = vert | Info = gris
"""

from __future__ import annotations

import os
import re
import sys

_WIDTH = 80

# ANSI (activé sur Windows 10+)
R = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[96m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"


def _enable_windows_ansi() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        return True
    return os.environ.get("TERM", "") != "dumb"


_enable_windows_ansi()
_USE_COLOR = _supports_color()


def _c(text: str, *codes: str) -> str:
    if not _USE_COLOR or not codes:
        return text
    return "".join(codes) + text + R


def _line(char: str, color: str) -> str:
    return _c(char * _WIDTH, color)


def banner(tp: int | str, title: str, subtitle: str = "") -> None:
    """Bannière d'ouverture du TP."""
    tag = f"TP {tp}" if isinstance(tp, int) else str(tp)
    print()
    print(_c("╔" + "═" * (_WIDTH - 2) + "╗", BOLD + BLUE))
    print(_c("║", BOLD + BLUE) + _c(f"  {tag} — {title}".center(_WIDTH - 2), BOLD + WHITE) + _c("║", BOLD + BLUE))
    if subtitle:
        print(_c("║", BOLD + BLUE) + _c(f"  {subtitle}".center(_WIDTH - 2), DIM + CYAN) + _c("║", BOLD + BLUE))
    print(_c("╚" + "═" * (_WIDTH - 2) + "╝", BOLD + BLUE))
    print()


def section(title: str) -> None:
    """Exercice principal (ex. EXERCICE 1.1)."""
    print()
    print(_line("═", BOLD + CYAN))
    print(_c(f"  EXERCICE │ {title}", BOLD + CYAN))
    print(_line("═", BOLD + CYAN))


def subsection(title: str) -> None:
    """Sous-partie : attaque/vulnérabilité en rouge, démo en jaune."""
    lower = title.lower()
    if any(k in lower for k in ("attaque", "attack", "vulnérabilit", "crib", "weakness")):
        attack(title)
        return
    demo(title)


def attack(title: str) -> None:
    """Bloc attaque / cryptanalyse."""
    print()
    print(_line("─", RED))
    print(_c(f"  ATTAQUE │ {title}", BOLD + RED))
    print(_line("─", RED))


def demo(title: str) -> None:
    """Démonstration chiffrement / protocole (hors attaque)."""
    print()
    print(_line("─", YELLOW))
    print(_c(f"  DÉMO │ {title}", BOLD + YELLOW))
    print(_line("─", YELLOW))


def summary(title: str) -> None:
    """Synthèse ou résumé final."""
    print()
    print(_line("═", BOLD + MAGENTA))
    print(_c(f"  SYNTHÈSE │ {title}", BOLD + MAGENTA))
    print(_line("═", BOLD + MAGENTA))


def end_footer(tp: int | str) -> None:
    print()
    print(_line("═", BOLD + GREEN))
    print(_c(f"  FIN DU TP {tp}".center(_WIDTH), BOLD + GREEN))
    print(_line("═", BOLD + GREEN))
    print()


def label(name: str, value: object) -> None:
    """Libellé + valeur (clair, clé, chiffré…)."""
    print(_c(f"  {name:<14}", BOLD + YELLOW) + _c(str(value), GREEN))


def info(text: str) -> None:
    print(_c(f"  {text}", DIM))


def ok(text: str) -> None:
    print(_c(f"  ✓ {text}", BOLD + GREEN))


def fail(text: str) -> None:
    print(_c(f"  ✗ {text}", BOLD + RED))


def warn(text: str) -> None:
    print(_c(f"  ⚠ {text}", BOLD + YELLOW))


def result(name: str, success: bool, ok_text: str = "OUI", fail_text: str = "NON") -> None:
    if success:
        ok(f"{name}: {ok_text}")
    else:
        fail(f"{name}: {fail_text}")


def error_exercise(num: str, exc: BaseException) -> None:
    fail(f"Erreur Exercice {num}: {exc}")


def colored_body(text: str) -> str:
    """Colorise ✓ ✗ → dans les blocs multilignes."""
    if not _USE_COLOR:
        return text
    out = text
    out = re.sub(r"✓", _c("✓", BOLD + GREEN), out)
    out = re.sub(r"✗", _c("✗", BOLD + RED), out)
    out = re.sub(r"→", _c("→", CYAN), out)
    return out


def print_block(text: str) -> None:
    print(colored_body(text))


# Alias pour compatibilité tp4/tp5
print_header = section
print_section = section
print_subsection = subsection
