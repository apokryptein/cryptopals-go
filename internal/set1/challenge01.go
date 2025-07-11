// Package set1 contains solution to Cryptopal's Set 1 problems
package set1

import (
	"fmt"

	"github.com/apokryptein/cryptopals-go/encoding"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         1,
		Number:      1,
		Name:        "Convert hex to base64",
		Description: "Convert a hex encoded string to base64",
		Implemented: true,
		Run:         runChallenge01,
	})
}

func Challenge01(hexString string) (string, error) {
	return encoding.HexToBase64(hexString)
}

func runChallenge01() error {
	hexInput := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	wantResult := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	// DEBUG
	fmt.Printf("Input Hex:  %s\n", hexInput)

	result, err := Challenge01(hexInput)
	if err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}

	// DEBUG
	fmt.Printf("Output:     %s\n", result)
	fmt.Printf("Expected:   %s\n", wantResult)

	// Check the result
	if result != wantResult {
		return fmt.Errorf("result doesn't match expected value")
	}

	// Alert
	fmt.Println("[i] Challenge passed")
	return nil
}
