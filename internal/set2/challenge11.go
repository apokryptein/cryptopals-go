package set2

import (
	"crypto/aes"
	"fmt"

	"github.com/apokryptein/cryptopals-go/internal/analysis"
)

func Challenge11(pt []byte) (mode string, result bool, err error) {
	// Instantiate new oracle
	oracle, err := analysis.NewOracle(analysis.ModeRandom)
	if err != nil {
		return "", false, fmt.Errorf("oracle creation failed: %w", err)
	}

	// Call oracle
	ct, modeUsed, err := oracle(pt)
	if err != nil {
		return "", false, fmt.Errorf("oracle failed: %w", err)
	}

	// Detect
	result = analysis.DetectAESECB(ct, aes.BlockSize)

	return modeUsed.String(), result, nil
}
