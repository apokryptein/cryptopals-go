package set1

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/apokryptein/cryptopals-go/crypto"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         1,
		Number:      7,
		Name:        "AES in ECB mode",
		Description: "Implementation of AES ECB decryption",
		Implemented: true,
		Run:         runChallenge07,
	})
}

func Challenge07(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("error reading file: %w", err)
	}

	cleanData := strings.ReplaceAll(string(data), "\n", "")
	decodedData, err := base64.StdEncoding.DecodeString(cleanData)
	if err != nil {
		return "", fmt.Errorf("error decoding data: %w", err)
	}

	key := "YELLOW SUBMARINE"

	pyBytes, _ := crypto.DecryptAESECB([]byte(key), decodedData)

	return string(pyBytes), nil
}

func runChallenge07() error {
	// Data
	wantResult := "I'm back and I'm ringin' the bell"

	// Run challenge
	pt, err := Challenge07("./testdata/set1-challenge07_data.txt")
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Split on newline
	lines := strings.Split(pt, "\n")

	// DEBUG
	fmt.Printf("Decrypted:  %s\n", lines[0])
	fmt.Printf("Expected:   %s\n", wantResult)

	// Check result
	if !strings.HasPrefix(pt, wantResult) {
		return fmt.Errorf("result doesn't match expected value: %w", err)
	}

	// Alert
	fmt.Println("[i] Challenge passed")

	return nil
}
