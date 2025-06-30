package set2

import (
	"crypto/aes"
	"fmt"

	"github.com/apokryptein/cryptopals-go/internal/cryptanalysis"
)

func Challenge11(pt []byte) (mode string, result bool, err error) {
	// Instantiate new oracle
	oracle, err := cryptanalysis.NewOracle(cryptanalysis.ModeRandom)
	if err != nil {
		return "", false, fmt.Errorf("oracle creation failed: %w", err)
	}

	// Call oracle
	ct, modeUsed, err := oracle(pt)
	if err != nil {
		return "", false, fmt.Errorf("oracle failed: %w", err)
	}

	// Detect
	result = cryptanalysis.DetectAES_ECB(ct, aes.BlockSize)

	return modeUsed.String(), result, nil
}
