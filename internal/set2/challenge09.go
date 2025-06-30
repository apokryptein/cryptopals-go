// Package set2 contains solution to Cryptopal's Set 2 problems
package set2

import (
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

func Challenge09(plaintext string, blockSize int) ([]byte, error) {
	paddedData, err := crypto.PaddingPKCS7([]byte(plaintext), blockSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	return paddedData, nil
}
