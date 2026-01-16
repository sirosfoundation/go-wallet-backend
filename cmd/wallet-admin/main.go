// Package main provides the wallet-admin CLI tool for managing the wallet backend.
package main

import (
	"os"

	"github.com/sirosfoundation/go-wallet-backend/cmd/wallet-admin/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
