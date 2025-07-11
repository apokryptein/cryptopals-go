package set2

import (
	"crypto/aes"
	"fmt"

	"github.com/apokryptein/cryptopals-go/analysis"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         2,
		Number:      11,
		Name:        "ECB/CBC detection oracle",
		Description: "Detect the cipher block mode from ciphertext encrypted using ECB or CBC mode",
		Implemented: true,
		// Run:         runChallenge11,
	})
}

func Challenge11(pt []byte) (mode string, result bool, err error) {
	// Instantiate new oracle
	oracle, err := analysis.NewOracle(analysis.WithMode(analysis.ModeRandom))
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
