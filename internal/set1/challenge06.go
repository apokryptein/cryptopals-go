package set1

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/apokryptein/cryptopals-go/analysis"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         1,
		Number:      6,
		Name:        "Break repeating-key XOR",
		Description: "Implementation of breaking repeating-key XOR",
		Implemented: true,
		Run:         runChallenge06,
	})
}

func Challenge06(filePath string) (key string, plaintext string, err error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", fmt.Errorf("error reading file: %w", err)
	}

	cleanData := strings.ReplaceAll(string(data), "\n", "")
	decodedData, err := base64.StdEncoding.DecodeString(cleanData)
	if err != nil {
		return "", "", fmt.Errorf("error decoding base64 string: %w", err)
	}

	keyBytes, pTextBytes, err := analysis.BreakRepeatingKeyXOR(decodedData)
	if err != nil {
		return "", "", fmt.Errorf("Challenge06: %v", err)
	}

	return string(keyBytes), string(pTextBytes), nil
}

func runChallenge06() error {
	// Data
	wantKey := "Terminator X: Bring the noise"
	wantPrefix := "I'm back and I'm ringin' the bell"

	// Run challenge
	key, plaintext, err := Challenge06("./testdata/set1-challenge06_data.txt")
	if err != nil {
		return fmt.Errorf("routine failed: %w", err)
	}

	// Split on newline
	lines := strings.Split(plaintext, "\n")

	// DEBUG
	fmt.Printf("Prefix:          %s\n", lines[0])
	fmt.Printf("Expected Prefix: %s\n", wantPrefix)

	// Check results
	if key != wantKey || !strings.HasPrefix(plaintext, wantPrefix) {
		return fmt.Errorf("result doesn't match expected value")
	}

	// Alert
	fmt.Println("[i] Challenge passed")

	return nil
}
