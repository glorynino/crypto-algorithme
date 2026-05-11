#!/bin/bash

###############################################################################
#                     TP3 - ASYMMETRIC CRYPTOGRAPHY TEST SUITE              #
#                                                                            #
#  This script runs the complete TP3 module (DH, RSA, ElGamal, ECC)        #
#  with comprehensive attack demonstrations.                                #
#                                                                            #
#  Usage:                                                                    #
#    ./run_tp3_tests.sh           (run with default settings)               #
#    ./run_tp3_tests.sh --verbose (detailed output)                         #
#    ./run_tp3_tests.sh --quiet   (minimal output)                          #
#                                                                            #
###############################################################################

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WORKSPACE="/home/matt-anis/Studies/Crypto"
PYTHON_CMD="python3"
LOG_FILE="tp3_test_results.log"
VERBOSE=false
QUIET=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --verbose)
            VERBOSE=true
            ;;
        --quiet)
            QUIET=true
            ;;
        --help)
            echo "Usage: ./run_tp3_tests.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --verbose    Print detailed output"
            echo "  --quiet      Minimal output"
            echo "  --help       Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

# Helper functions
log_header() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
}

log_section() {
    echo -e "${YELLOW}▶ $1${NC}"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

log_error() {
    echo -e "${RED}✗ $1${NC}"
}

log_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Main execution
main() {
    cd "$WORKSPACE"
    
    log_header "TP3 - ASYMMETRIC CRYPTOGRAPHY TEST SUITE"
    echo ""
    log_info "Workspace: $WORKSPACE"
    log_info "Python: $(${PYTHON_CMD} --version)"
    log_info "Log file: $LOG_FILE"
    echo ""
    
    # Check Python version
    PYTHON_VERSION=$(${PYTHON_CMD} -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if ! ${PYTHON_CMD} -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
        log_error "Python 3.8+ required (found $PYTHON_VERSION)"
        exit 1
    fi
    log_success "Python version compatible: $PYTHON_VERSION"
    echo ""
    
    # Check required files
    log_section "Checking required files..."
    REQUIRED_FILES=(
        "DH/dh.py"
        "DH/dh_attacks.py"
        "RSA/rsa.py"
        "RSA/rsa_attacks.py"
        "ElGamal/elgamal.py"
        "ElGamal/elgamal_attacks.py"
        "ECC/ecc.py"
        "ECC/ecc_attacks.py"
        "tp3_complete.py"
    )
    
    MISSING_FILES=0
    for file in "${REQUIRED_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            log_success "Found: $file"
        else
            log_error "Missing: $file"
            ((MISSING_FILES++))
        fi
    done
    
    if [[ $MISSING_FILES -gt 0 ]]; then
        log_error "Missing $MISSING_FILES required file(s)"
        exit 1
    fi
    echo ""
    
    # Check dependencies
    log_section "Checking Python dependencies..."
    for module in sympy math hashlib random; do
        if ${PYTHON_CMD} -c "import $module" 2>/dev/null; then
            log_success "Module available: $module"
        else
            log_error "Module missing: $module"
            exit 1
        fi
    done
    echo ""
    
    # Run tests
    log_section "Running TP3 test suite..."
    echo ""
    
    START_TIME=$(date +%s)
    
    if [[ "$VERBOSE" == true ]]; then
        ${PYTHON_CMD} tp3_complete.py 2>&1 | tee "$LOG_FILE"
        TEST_EXIT_CODE=${PIPESTATUS[0]}
    elif [[ "$QUIET" == true ]]; then
        ${PYTHON_CMD} tp3_complete.py > "$LOG_FILE" 2>&1
        TEST_EXIT_CODE=$?
    else
        ${PYTHON_CMD} tp3_complete.py 2>&1 | tee -a "$LOG_FILE"
        TEST_EXIT_CODE=$?
    fi
    
    END_TIME=$(date +%s)
    ELAPSED=$((END_TIME - START_TIME))
    
    echo ""
    
    # Results summary
    if [[ $TEST_EXIT_CODE -eq 0 ]]; then
        log_header "TEST SUITE COMPLETE ✓"
        
        log_success "All exercises completed successfully"
        log_info "Execution time: ${ELAPSED}s"
        log_info "Results saved to: $LOG_FILE"
        
        # Print summary from log
        echo ""
        log_section "Key Results Summary:"
        if grep -q "Exercise 3.1" "$LOG_FILE"; then
            grep "Exercise 3.1" "$LOG_FILE" | head -1
        fi
        if grep -q "Exercise 3.2" "$LOG_FILE"; then
            grep "Exercise 3.2" "$LOG_FILE" | head -1
        fi
        if grep -q "Exercise 3.3" "$LOG_FILE"; then
            grep "Exercise 3.3" "$LOG_FILE" | head -1
        fi
        if grep -q "Exercise 3.4" "$LOG_FILE"; then
            grep "Exercise 3.4" "$LOG_FILE" | head -1
        fi
        
        echo ""
        log_section "Run individual tests:"
        echo "  python3 DH/dh.py"
        echo "  python3 DH/dh_attacks.py"
        echo "  python3 RSA/rsa.py"
        echo "  python3 RSA/rsa_attacks.py"
        echo "  python3 ElGamal/elgamal.py"
        echo "  python3 ElGamal/elgamal_attacks.py"
        echo "  python3 ECC/ecc.py"
        echo "  python3 ECC/ecc_attacks.py"
        
        echo ""
        log_section "Documentation:"
        echo "  View: TP3_README.md       (Exercise guide)"
        echo "  View: TP3_SUMMARY.md      (Completion report)"
        echo "  View: $LOG_FILE (Test output)"
        
        exit 0
    else
        log_header "TEST SUITE FAILED ✗"
        
        log_error "Tests exited with code: $TEST_EXIT_CODE"
        log_info "Execution time: ${ELAPSED}s"
        log_info "Check log for details: $LOG_FILE"
        
        echo ""
        log_section "Error diagnostics:"
        tail -30 "$LOG_FILE" | while read line; do
            echo "  $line"
        done
        
        exit 1
    fi
}

# Run main function
main "$@"
