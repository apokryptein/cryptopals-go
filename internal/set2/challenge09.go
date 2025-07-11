// Package set2 contains solution to Cryptopal's Set 2 problems
package set2

import (
	"fmt"
	"os"
	"strings"

	"github.com/apokryptein/cryptopals-go/crypto"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         2,
		Number:      9,
		Name:        "Implement PKCS#7 Padding",
		Description: "Implement PKCS#7 Padding",
		Implemented: true,
		Run:         runChallenge09,
	})
}

func Challenge09(plaintext string, blockSize int) ([]byte, error) {
	paddedData, err := crypto.PaddingPKCS7([]byte(plaintext), blockSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	return paddedData, nil
}

func runChallenge09() error {
	// Data
	wantSize := 25 // blockSize to match desired length
	wantString := "YELLOW SUBMARINE"

	// Run challenge
	result, err := Challenge09(wantString, wantSize)
	if err != nil {
		return fmt.Errorf("padding failed: %w", err)
	}

	// DEBUG
	fmt.Printf("Size:          %d\n", len(result))
	fmt.Printf("Expected size: %d\n", wantSize)

	// Check result
	if !strings.HasPrefix(string(result), wantString) || len(result) != wantSize {
		return fmt.Errorf("result doens't match expect value")
	}

	// Alert
	fmt.Println("[i] Challenge passed")
	return nil
}
