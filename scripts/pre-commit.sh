#!/usr/bin/env bash
# Pre-commit hook for go-wallet-backend
# Runs gofmt and golangci-lint before each commit to catch common issues
#
# Tests are run separately via CI/CD and `make test`

set -e

echo "Running pre-commit checks..."

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    echo "Error: go.mod not found. Run this from the project root."
    exit 1
fi

# Check for staged Go files
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep "\.go$" || true)
if [ -z "$STAGED_GO_FILES" ]; then
    echo "No Go files staged, skipping checks."
    exit 0
fi

# Run gofmt first
echo "Checking formatting..."
UNFORMATTED=$(gofmt -s -l $STAGED_GO_FILES 2>&1 || true)
if [ -n "$UNFORMATTED" ]; then
    echo "The following files are not formatted:"
    echo "$UNFORMATTED"
    echo ""
    echo "Run 'gofmt -s -w .' to fix, then re-stage the files."
    exit 1
fi
echo "✓ Formatting OK"

# Check if golangci-lint is installed
if ! command -v golangci-lint &> /dev/null; then
    echo "⚠ golangci-lint not installed, skipping lint check"
    echo "  Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
    exit 0
fi

# Run golangci-lint
echo "Running golangci-lint..."
if ! golangci-lint run ./... 2>&1; then
    echo "golangci-lint failed - fix issues before committing"
    exit 1
fi
echo "✓ Lint passed"

echo "All pre-commit checks passed."
exit 0
