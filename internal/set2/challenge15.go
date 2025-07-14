package set2

import (
	"crypto/aes"
	"fmt"

	"github.com/apokryptein/cryptopals-go/crypto"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         2,
		Number:      15,
		Name:        "PKCS#7 padding validation",
		Description: "Determine if plaintext has valid PKCS#7 padding, and strip the padding off",
		Implemented: true,
		Run:         runChallenge15,
	})
}

func Challenge15(pt []byte) ([]byte, error) {
	// Validate padding
	stripped, err := crypto.ValidatePadding(pt, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("padding validation failed: %w", err)
	}

	return stripped, nil
}

func runChallenge15() error {
	// Test data
	testData := "ICE ICE BABY\x04\x04\x04\x04"
	want := "ICE ICE BABY"

	// Run challenge
	stripped, err := Challenge15([]byte(testData))
	if err != nil {
		return fmt.Errorf("padding validation failed: %w", err)
	}

	// DEBUG
	fmt.Printf("Stripped plaintext: %s\n", string(stripped))
	fmt.Printf("Expected plaintext: %s\n", want)

	// Validate result
	if want != string(stripped) {
		return fmt.Errorf("result doesn't match expected value")
	}

	// Alert
	fmt.Println("[i] Challenge passed")

	return nil
}
