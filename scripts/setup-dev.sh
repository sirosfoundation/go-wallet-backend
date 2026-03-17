#!/bin/bash
#
# Developer environment setup script for go-wallet-backend
#
# This script sets up the development environment including:
# - Installing Git hooks
# - Installing development tools
# - Running initial checks
#

set -e

echo "🚀 Setting up go-wallet-backend development environment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    echo -e "${RED}Error: go.mod not found. Run this from the project root.${NC}"
    exit 1
fi

echo -e "${BLUE}Step 1: Checking Go installation...${NC}"
if ! command -v go &> /dev/null; then
    echo -e "${RED}Error: Go is not installed${NC}"
    exit 1
fi
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo -e "${GREEN}✓ Go version ${GO_VERSION} detected${NC}"

echo -e "${BLUE}Step 2: Installing development tools...${NC}"
if [ -f "Makefile" ] && grep -q "tools:" Makefile; then
    make tools 2>/dev/null || true
else
    echo -e "${YELLOW}Installing golangci-lint...${NC}"
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
fi
echo -e "${GREEN}✓ Development tools installed${NC}"

echo -e "${BLUE}Step 3: Setting up Git hooks...${NC}"
if [ -d ".git" ]; then
    # Install pre-commit hook
    if [ -f "scripts/pre-commit.sh" ]; then
        ln -sf ../../scripts/pre-commit.sh .git/hooks/pre-commit
        chmod +x scripts/pre-commit.sh
        chmod +x .git/hooks/pre-commit
        echo -e "${GREEN}✓ Pre-commit hook installed${NC}"
    else
        echo -e "${YELLOW}⚠️  Pre-commit script not found${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Not a git repository, skipping hook installation${NC}"
fi

echo -e "${BLUE}Step 4: Downloading dependencies...${NC}"
go mod download
echo -e "${GREEN}✓ Dependencies downloaded${NC}"

echo -e "${BLUE}Step 5: Running initial checks...${NC}"

# Run linter
echo -e "  ${YELLOW}→ Running linter...${NC}"
if command -v golangci-lint &> /dev/null; then
    if golangci-lint run ./... > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓ Linter passed${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Some lint issues found (this might be expected)${NC}"
    fi
else
    echo -e "  ${YELLOW}⚠️  golangci-lint not found, skipping lint check${NC}"
fi

# Run tests
echo -e "  ${YELLOW}→ Running tests...${NC}"
if make test > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓ Tests passed${NC}"
else
    echo -e "  ${YELLOW}⚠️  Some tests failed (this might be expected)${NC}"
fi

echo ""
echo -e "${GREEN}✅ Development environment setup complete!${NC}"
echo ""
echo -e "${BLUE}Useful commands:${NC}"
echo -e "  ${YELLOW}make help${NC}           - Show all available make targets"
echo -e "  ${YELLOW}make test${NC}           - Run all tests"
echo -e "  ${YELLOW}make lint${NC}           - Run linter"
echo -e "  ${YELLOW}make build${NC}          - Build the server binary"
echo -e "  ${YELLOW}make build-all${NC}      - Build all binaries"
echo -e "  ${YELLOW}make test-coverage${NC}  - Run tests with coverage"
echo ""
echo -e "${BLUE}Git hooks installed:${NC}"
echo -e "  ${YELLOW}pre-commit${NC}    - Runs golangci-lint and tests before each commit"
echo ""
