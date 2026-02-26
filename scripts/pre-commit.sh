#!/usr/bin/env bash
# Pre-commit hook for go-wallet-backend
# This hook runs before each commit to ensure code quality
#
# To install this hook, run:
#   ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit
#   chmod +x scripts/pre-commit.sh

set -e

echo "Running pre-commit checks..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    echo -e "${RED}Error: go.mod not found. Run this from the project root.${NC}"
    exit 1
fi

# Check if golangci-lint is installed
check_golangci_lint() {
    if ! command -v golangci-lint &> /dev/null; then
        echo -e "${RED}✗ golangci-lint is not installed${NC}"
        echo -e "${YELLOW}  Install it with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest${NC}"
        echo -e "${YELLOW}  Or run: make tools${NC}"
        return 1
    fi
    return 0
}

# 1. Run golangci-lint (comprehensive linting including format, vet, and more)
echo -e "${YELLOW}→ Running golangci-lint...${NC}"
if check_golangci_lint; then
    # Run golangci-lint on staged Go files only for speed
    STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep "\.go$" || true)
    if [ -n "$STAGED_GO_FILES" ]; then
        if ! golangci-lint run --new-from-rev=HEAD~0 ./... 2>&1; then
            echo -e "${RED}✗ golangci-lint failed${NC}"
            echo -e "${YELLOW}  Fix the issues above and try again${NC}"
            echo -e "${YELLOW}  Run: golangci-lint run ./... to see all issues${NC}"
            exit 1
        fi
        echo -e "${GREEN}✓ golangci-lint passed${NC}"
    else
        echo -e "${GREEN}✓ No Go files to lint${NC}"
    fi
else
    # Fallback: basic checks if golangci-lint not installed
    echo -e "${YELLOW}⚠ Falling back to basic checks...${NC}"
    
    # Format check
    echo -e "${YELLOW}→ Checking code formatting...${NC}"
    UNFORMATTED=$(gofmt -l . 2>&1 | grep -v "vendor/" | grep ".go$" || true)
    if [ -n "$UNFORMATTED" ]; then
        echo -e "${RED}✗ The following files are not formatted:${NC}"
        echo "$UNFORMATTED"
        echo -e "${YELLOW}  Run: gofmt -s -w .${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Code formatting OK${NC}"
    
    # Go vet
    echo -e "${YELLOW}→ Running go vet...${NC}"
    VET_OUTPUT=$(go vet ./... 2>&1 | grep -v "vendor/" || true)
    if [ -n "$VET_OUTPUT" ]; then
        echo -e "${RED}✗ go vet failed${NC}"
        echo "$VET_OUTPUT"
        exit 1
    fi
    echo -e "${GREEN}✓ go vet passed${NC}"
fi

# 2. Run tests (short tests only for speed)
echo -e "${YELLOW}→ Running tests...${NC}"
if ! go test -short -race -timeout 2m ./... > /dev/null 2>&1; then
    echo -e "${RED}✗ Tests failed${NC}"
    echo -e "${YELLOW}  Run: make test${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Tests passed${NC}"

# 3. Check for common issues
echo -e "${YELLOW}→ Checking for common issues...${NC}"

# Check for debugging statements
DEBUGGING=$(grep -rn "fmt.Print" --include="*.go" . | grep -v "vendor/" | grep -v "_test.go" | grep -v "cmd/" || true)
if [ -n "$DEBUGGING" ]; then
    echo -e "${YELLOW}⚠ Warning: Found fmt.Print* statements (debugging?):${NC}"
    echo "$DEBUGGING"
fi

# Check for TODO/FIXME
TODOS=$(grep -rn "TODO\|FIXME" --include="*.go" . | grep -v "vendor/" || true)
if [ -n "$TODOS" ]; then
    echo -e "${YELLOW}⚠ Warning: Found TODO/FIXME comments:${NC}"
    echo "$TODOS" | head -5
    if [ $(echo "$TODOS" | wc -l) -gt 5 ]; then
        echo "  ... and $(( $(echo "$TODOS" | wc -l) - 5 )) more"
    fi
fi

echo -e "${GREEN}✓ Common issues check complete${NC}"

# 4. Check go.mod/go.sum
echo -e "${YELLOW}→ Checking go.mod and go.sum...${NC}"
if ! git diff --cached --name-only | grep -q "go.mod"; then
    # go.mod not staged, check if it needs updating
    go mod tidy
    if git diff --exit-code go.mod go.sum > /dev/null 2>&1; then
        echo -e "${GREEN}✓ go.mod and go.sum are up to date${NC}"
    else
        echo -e "${RED}✗ go.mod or go.sum needs updating${NC}"
        echo -e "${YELLOW}  Run: go mod tidy${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓ go.mod changes staged${NC}"
fi

echo -e "${GREEN}✓ All pre-commit checks passed!${NC}"
exit 0
