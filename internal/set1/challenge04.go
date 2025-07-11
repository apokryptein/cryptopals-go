package set1

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/analysis"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         1,
		Number:      4,
		Name:        "Detect single-character XOR",
		Description: "Locate entry in file that has been encrypted using single-character XOR",
		Implemented: true,
		Run:         runChallenge04,
	})
}

func Challenge04(filePath string) (encData string, decData string, key string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", "", fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var result struct {
		EncryptedData string
		DecryptedData string
		Key           string
	}

	var maxScore float64
	// Instantiate new scanner
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Store current line
		currentLine := scanner.Text()

		// Decode hex
		hexBytes, err := hex.DecodeString(currentLine)
		if err != nil {
			continue
		}

		key, message, score, err := analysis.BruteSingleByteXOR(hexBytes)
		if err != nil {
			return "", "", "", fmt.Errorf("error bruteforcing message: %w", err)
		}

		// Check score
		if score > maxScore {
			maxScore = score
			result.EncryptedData = currentLine
			result.DecryptedData = string(message)
			result.Key = string(key)
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		return "", "", "", fmt.Errorf("error scanning file: %w", err)
	}

	return result.EncryptedData, result.DecryptedData, result.Key, nil
}

func runChallenge04() error {
	// Data
	wantEncrypted := "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
	wantDecrypted := "Now that the party is jumping"
	wantKey := "5"

	// Data file path
	filePath := "./testdata/set1-challenge04_data.txt"

	// Run challenge
	encrypted, decrypted, key, err := Challenge04(filePath)
	if err != nil {
		return fmt.Errorf("detection failed: %w", err)
	}

	// DEBUG
	fmt.Printf("Key:               %s\n", key)
	fmt.Printf("Expected Key:      %s\n", wantKey)
	fmt.Printf("Message:           %s\n", decrypted)
	fmt.Printf("Expected Message:  %s\n", wantDecrypted)

	// Check the result
	if encrypted != wantEncrypted || decrypted != wantDecrypted || key != wantKey {
		return fmt.Errorf("result doesn't match expected value")
	}

	// Alert
	fmt.Println("[i] Challenge passed")

	return nil
}
