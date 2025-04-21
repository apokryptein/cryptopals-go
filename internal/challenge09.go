package set2

import (
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

func Challenge09(key string, blockSize int) ([]byte, error) {
	newKey, err := crypto.PaddingPKCS7([]byte(key), blockSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	return newKey, nil
}
