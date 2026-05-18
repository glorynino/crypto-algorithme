#!/bin/bash
# TP 1 - Quick Execution Script (paths relative to this file)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

if [ -x "$SCRIPT_DIR/env/bin/python3" ]; then
    PYTHON="$SCRIPT_DIR/env/bin/python3"
elif [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then
    PYTHON="$SCRIPT_DIR/.venv/bin/python3"
elif [ -x "$SCRIPT_DIR/env/Scripts/python.exe" ]; then
    PYTHON="$SCRIPT_DIR/env/Scripts/python.exe"
else
    PYTHON="$(command -v python3 || command -v python)"
fi

if [ -z "$PYTHON" ] || [ ! -x "$PYTHON" ]; then
    echo "Python not found. Create the venv: python -m venv env && pip install -r requirements.txt"
    exit 1
fi

echo "╔════════════════════════════════════════════════════╗"
echo "║     TP 1 - CHIFFREMENT CLASSIQUE                  ║"
echo "║  Caesar, Vigenère, Hill, OTP Demonstrator         ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "Project: $SCRIPT_DIR"
echo "Python:  $PYTHON"
echo ""

echo "Available tests:"
echo "  1. Quick test (Caesar cipher only)"
echo "  2. All Caesar attacks"
echo "  3. All Vigenère attacks"
echo "  4. All Hill cipher attacks"
echo "  5. All OTP attacks"
echo "  6. Complete TP1 suite (all exercises)"
echo "  7. Run individual module tests"
echo ""

if [ -z "$1" ]; then
    echo "Usage: $0 [1-7]"
    echo "Example: $0 6"
    exit 0
fi

case "$1" in
    1)
        echo "Running: Quick Caesar Test..."
        "$PYTHON" test_tp1_quick.py
        ;;
    2)
        echo "Running: Caesar Attacks..."
        cd "Caesar cipher" && "$PYTHON" caesar_attacks.py
        ;;
    3)
        echo "Running: Vigenère Attacks..."
        cd "Vignere cipher" && "$PYTHON" vignere_attacks.py
        ;;
    4)
        echo "Running: Hill Cipher Attacks..."
        cd "HILL" && "$PYTHON" hill_attacks.py
        ;;
    5)
        echo "Running: OTP Attacks..."
        cd "OTP algorithm" && "$PYTHON" otp_attacks.py
        ;;
    6)
        echo "Running: Complete TP1 Suite..."
        "$PYTHON" tp1_complete.py
        ;;
    7)
        echo "Running individual unit tests..."
        echo ""
        echo ">>> Caesar tests"
        (cd "Caesar cipher" && "$PYTHON" tests.py)
        echo ""
        echo ">>> Vigenère tests"
        (cd "Vignere cipher" && "$PYTHON" tests.py)
        echo ""
        echo ">>> Hill tests"
        (cd "HILL" && "$PYTHON" tests.py)
        echo ""
        echo ">>> OTP tests"
        (cd "OTP algorithm" && "$PYTHON" tests.py)
        ;;
    *)
        echo "Invalid choice. Please use 1-7"
        exit 1
        ;;
esac

echo ""
echo "Test completed."
