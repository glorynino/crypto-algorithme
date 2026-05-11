#!/bin/bash
# TP 1 - Quick Execution Script

echo "╔════════════════════════════════════════════════════╗"
echo "║     TP 1 - CHIFFREMENT CLASSIQUE                  ║"
echo "║  Caesar, Vigenère, Hill, OTP Demonstrator         ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""

CRYPTO_DIR="/home/matt-anis/Studies/Crypto"
PYTHON="${CRYPTO_DIR}/.venv/bin/python3"

# Check if venv exists
if [ ! -f "$PYTHON" ]; then
    echo "❌ Python venv not found. Please activate first."
    exit 1
fi

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
    echo "Example: $0 1"
    exit 0
fi

cd "$CRYPTO_DIR"

case "$1" in
    1)
        echo "Running: Quick Caesar Test..."
        "$PYTHON" test_tp1_quick.py
        ;;
    2)
        echo "Running: Caesar Attacks..."
        cd "Caesar cipher"
        "$PYTHON" caesar_attacks.py
        ;;
    3)
        echo "Running: Vigenère Attacks..."
        cd "Vignere cipher"
        "$PYTHON" vignere_attacks.py
        ;;
    4)
        echo "Running: Hill Cipher Attacks..."
        cd "HILL"
        "$PYTHON" hill_attacks.py
        ;;
    5)
        echo "Running: OTP Attacks..."
        cd "OTP algorithm"
        "$PYTHON" otp_attacks.py
        ;;
    6)
        echo "Running: Complete TP1 Suite..."
        "$PYTHON" tp1_complete.py
        ;;
    7)
        echo "Running individual unit tests..."
        echo ""
        echo ">>> Caesar tests"
        cd "Caesar cipher" && "$PYTHON" tests.py
        echo ""
        echo ">>> Vigenère tests"
        cd ../Vignere\ cipher && "$PYTHON" tests.py
        echo ""
        echo ">>> Hill tests"
        cd ../HILL && "$PYTHON" tests.py
        echo ""
        echo ">>> OTP tests"
        cd ../OTP\ algorithm && "$PYTHON" tests.py
        ;;
    *)
        echo "❌ Invalid choice. Please use 1-7"
        exit 1
        ;;
esac

echo ""
echo "✅ Test completed!"
