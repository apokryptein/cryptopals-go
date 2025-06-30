package set2

import (
	"crypto/aes"
	"fmt"

	"github.com/apokryptein/cryptopals-go/internal/cryptanalysis"
)

func Challenge11(pt []byte) (mode string, result bool, err error) {
	// Call oracle
	ct, mode, err := cryptanalysis.EncryptionOracle([]byte(pt), cryptanalysis.Random)
	if err != nil {
		return "", false, fmt.Errorf("oracle failed: %w", err)
	}

	// Detect
	result = cryptanalysis.DetectAES_ECB(ct, aes.BlockSize)

	return mode, result, nil
}
