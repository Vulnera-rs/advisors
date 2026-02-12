#!/bin/bash
# Local testing script for Vulnera Advisors
# Run all tests and checks locally before pushing

set -e

echo "🧪 Vulnera Advisors - Local Test Suite"
echo "======================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

FAILED=0
SKIPPED=0

# Parse arguments
VERBOSE=false
SKIP_OPTIONAL=false
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -v|--verbose) VERBOSE=true ;;
        --skip-optional) SKIP_OPTIONAL=true ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose       Show full output for each test"
            echo "  --skip-optional     Skip optional checks (audit, machete)"
            echo "  -h, --help          Show this help message"
            exit 0
            ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Function to run a test
run_test() {
    local name=$1
    local cmd=$2
    
    echo -n "▶ $name ... "
    if $VERBOSE; then
        echo ""
        if eval "$cmd"; then
            echo -e "${GREEN}✓ Passed${NC}"
        else
            echo -e "${RED}✗ Failed${NC}"
            FAILED=$((FAILED + 1))
        fi
    else
        if eval "$cmd" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${RED}✗${NC}"
            FAILED=$((FAILED + 1))
        fi
    fi
}

# Function to run an optional test (skips if tool not found)
run_optional_test() {
    local name=$1
    local tool=$2
    local cmd=$3
    
    if $SKIP_OPTIONAL; then
        echo -e "▶ $name ... ${YELLOW}skipped${NC}"
        SKIPPED=$((SKIPPED + 1))
        return
    fi
    
    if ! command -v "$tool" &> /dev/null; then
        echo -e "▶ $name ... ${YELLOW}skipped (${tool} not installed)${NC}"
        SKIPPED=$((SKIPPED + 1))
        return
    fi
    
    run_test "$name" "$cmd"
}

# Function to run a test with output
run_test_verbose() {
    local name=$1
    local cmd=$2
    
    echo -e "\n${YELLOW}▶ $name${NC}"
    if eval "$cmd"; then
        echo -e "${GREEN}✓ Passed${NC}\n"
    else
        echo -e "${RED}✗ Failed${NC}\n"
        FAILED=$((FAILED + 1))
    fi
}

echo -e "${BLUE}=== Core Checks ===${NC}"

# Check formatting
run_test "Formatting (cargo fmt)" "cargo fmt -- --check"

# Check clippy lints
run_test "Linting (cargo clippy)" "cargo clippy --all-targets --all-features -- -D warnings"

# Check for common mistakes
run_test "Cargo check" "cargo check --all-targets --all-features"

echo ""
echo -e "${BLUE}=== Tests ===${NC}"

# Unit tests
run_test "Unit tests" "cargo test --lib"

# Doc tests
run_test "Doc tests" "cargo test --doc"

# CWE filtering tests (matches all tests with 'cwe' in name)
run_test "CWE filtering tests" "cargo test --lib cwe"

echo ""
echo -e "${BLUE}=== Documentation ===${NC}"

# Build documentation
run_test "Documentation" "cargo doc --no-deps --all-features"

echo ""
echo -e "${BLUE}=== Optional Checks ===${NC}"

# Security audit (optional - requires cargo-audit)
run_optional_test "Security audit" "cargo-audit" "cargo audit"

# Check for unused dependencies (optional - requires cargo-machete)
run_optional_test "Unused dependencies" "cargo-machete" "cargo machete"

# Check for outdated dependencies (optional - requires cargo-outdated)
run_optional_test "Outdated dependencies" "cargo-outdated" "cargo outdated --exit-code 1"

echo ""
echo "======================================"
if [ $FAILED -eq 0 ]; then
    if [ $SKIPPED -gt 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC} (${YELLOW}$SKIPPED skipped${NC})"
    else
        echo -e "${GREEN}✓ All tests passed!${NC}"
    fi
    echo ""
    echo "You can now:"
    echo "  • Run 'cargo publish --dry-run' to test publishing"
    echo "  • Commit and push your changes"
    exit 0
else
    echo -e "${RED}✗ $FAILED test(s) failed${NC}"
    if [ $SKIPPED -gt 0 ]; then
        echo -e "${YELLOW}  $SKIPPED test(s) skipped${NC}"
    fi
    echo ""
    echo "Please fix the issues above before committing."
    exit 1
fi
