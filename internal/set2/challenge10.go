package set2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/apokryptein/cryptopals-go/crypto"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         2,
		Number:      10,
		Name:        "Implement CBC mode",
		Description: "Implement AES using Cipher Block Chaining (CBC) mode",
		Implemented: true,
		Run:         runChallenge10,
	})
}

func Challenge10(filePath string) ([]byte, error) {
	key := "YELLOW SUBMARINE"

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}

	cleanData := strings.ReplaceAll(string(data), "\n", "")
	decData, err := base64.StdEncoding.DecodeString(cleanData)
	if err != nil {
		return nil, fmt.Errorf("error decoding hex: %w", err)
	}

	// Manually set IV to 16 null bytes as per challenge instructions
	iv := bytes.Repeat([]byte("0"), 16)

	pt, err := crypto.DecryptAESCBC([]byte(key), iv, []byte(decData))
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return pt, nil
}

func runChallenge10() error {
	// Data
	want := []byte{121, 23, 93, 16, 82, 81, 83, 91, 16, 81, 94, 84, 16, 121, 23, 93}

	// Run challenge
	result, err := Challenge10("./testdata/set2-challenge10_data.txt")
	if err != nil {
		return fmt.Errorf("cbc decryption failed: %w", err)
	}

	// DEBUG
	fmt.Printf("Result:   %v\n", result[:16])
	fmt.Printf("Expected: %v\n", want)

	// Check
	if !slices.Equal(want, result[:16]) {
		return fmt.Errorf("result doesn't match expected value")
	}

	// Alert
	fmt.Println("[i] Challenge passed")

	return nil
}
