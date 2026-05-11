#!/bin/bash

# TP 2 - CRYPTOGRAPHIE SYMÉTRIQUE MODERNE
# Complete test runner for RC4, DES, AES, NIST Finalists

set -e  # Exit on error

CRYPTO_ROOT="/home/matt-anis/Studies/Crypto"
VENV="${CRYPTO_ROOT}/.venv"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  $1${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
}

print_section() {
    echo -e "${YELLOW}─── $1 ───${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check environment
print_header "TP 2 - CRYPTOGRAPHIE SYMÉTRIQUE MODERNE"
echo ""

# Verify workspace exists
if [ ! -d "$CRYPTO_ROOT" ]; then
    print_error "Workspace not found: $CRYPTO_ROOT"
    exit 1
fi
print_success "Workspace found: $CRYPTO_ROOT"

# Check virtualenv
if [ ! -d "$VENV" ]; then
    print_error "Python virtualenv not found: $VENV"
    echo "Create with: cd $CRYPTO_ROOT && python3 -m venv .venv"
    exit 1
fi
print_success "Python environment found"

# Activate virtualenv
source "$VENV/bin/activate"
print_success "Python environment activated"

# Verify Python packages
echo ""
print_section "Checking Dependencies"

python3 -c "import Crypto" && print_success "pycryptodome installed" || print_error "pycryptodome missing"
python3 -c "import cryptography" && print_success "cryptography installed" || print_error "cryptography missing"

# Run comprehensive test suite
echo ""
print_section "Running Complete TP2 Test Suite"
echo ""

cd "$CRYPTO_ROOT"

# Execute main test suite
python3 tp2_complete.py

# Optional: Run individual exercises
if [ "$1" == "--verbose" ]; then
    echo ""
    print_section "Running Individual Exercises (Verbose)"
    
    echo ""
    print_section "Exercise 2.1 - RC4"
    python3 RC4/rc4_attacks.py
    
    echo ""
    print_section "Exercise 2.2 - DES"
    python3 DES/des_modes.py
    
    echo ""
    print_section "Exercise 2.3 - AES"
    python3 AES/aes_modes.py
    
    echo ""
    print_section "Exercise 2.4 - NIST Finalists"
    python3 AES/nist_finalists.py
fi

echo ""
print_header "TP 2 TESTS COMPLETE"
echo ""
echo "Documentation:"
echo "  • TP2_README.md - Exercise guide and details"
echo "  • TP2_SUMMARY.md - Completion status and results"
echo ""
echo "Command to re-run:"
echo "  cd $CRYPTO_ROOT && bash run_tp2_tests.sh"
echo ""
echo "Verbose output:"
echo "  cd $CRYPTO_ROOT && bash run_tp2_tests.sh --verbose"
echo ""
