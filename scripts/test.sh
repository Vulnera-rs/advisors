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
NC='\033[0m' # No Color

FAILED=0

# Function to run a test
run_test() {
    local name=$1
    local cmd=$2
    
    echo -n "▶ $name ... "
    if eval "$cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        FAILED=$((FAILED + 1))
    fi
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

# Check formatting
run_test "Formatting (cargo fmt)" "cargo fmt -- --check"

# Check clippy lints
run_test "Linting (cargo clippy)" "cargo clippy --all-targets --all-features -- -D warnings"

# Check for common mistakes
run_test "Cargo check" "cargo check --all-targets --all-features"

# Unit tests
run_test "Unit tests" "cargo test --lib"

# Doc tests
run_test "Doc tests" "cargo test --doc"

# Build documentation
run_test "Documentation" "cargo doc --no-deps --all-features"

# Security audit
run_test "Security audit" "cargo audit"

# Check for deprecated dependencies
run_test "Check for unused dependencies" "cargo machete"

echo ""
echo "======================================"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    echo ""
    echo "You can now:"
    echo "  • Run 'cargo publish --dry-run' to test publishing"
    echo "  • Commit and push your changes"
    exit 0
else
    echo -e "${RED}✗ $FAILED test(s) failed${NC}"
    echo ""
    echo "Please fix the issues above before committing."
    exit 1
fi
