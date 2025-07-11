package set2

import (
	"bytes"
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
		Run:         runChallenge11,
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

func runChallenge11() error {
	const numTests = 1000
	var correctDetections int

	for range numTests {
		// Generate repeated plaintext
		pt := bytes.Repeat([]byte("A"), 128)

		// Run challege
		mode, result, err := Challenge11(pt)
		if err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}

		// Evaluate result
		if (mode == "ModeECB" && result) || (mode == "ModeCBC" && !result) {
			correctDetections++
		} else {
			return fmt.Errorf("result doesn't match expected value")
		}
	}

	// Calculate success rate
	successRate := float64(correctDetections) / float64(numTests)
	fmt.Printf("Success rate: %.2f%%\n", successRate*100)

	if successRate < 0.90 {
		return fmt.Errorf("detection accuracy too low:  %.2f%%", successRate*100)
	}

	// Alert
	fmt.Println("[i] Challenge passed")

	return nil
}
