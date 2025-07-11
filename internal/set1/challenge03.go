package set1

import (
	"encoding/hex"
	"fmt"

	analysis "github.com/apokryptein/cryptopals-go/analysis"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         1,
		Number:      3,
		Name:        "Single-byte XOR cipher",
		Description: "Find the key and decrypt a message",
		Implemented: true,
		Run:         runChallenge03,
	})
}

func Challenge03(messageEnc string) (key, message string, score float64, err error) {
	// Decode hex string to bytes
	messageBytes, err := hex.DecodeString(messageEnc)
	if err != nil {
		return "", "", 0, fmt.Errorf("error decoding hex string: %w", err)
	}

	keyByte, messageBytes, score, err := analysis.BruteSingleByteXOR(messageBytes)
	if err != nil {
		return "", "", 0, fmt.Errorf("error bruteforcing message: %w", err)
	}

	return string(keyByte), string(messageBytes), score, nil
}

func runChallenge03() error {
	// Data
	messageEnc := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	wantMessage := "Cooking MC's like a pound of bacon"
	wantKey := "X"

	// Run the challenge
	key, message, _, err := Challenge03(messageEnc)
	if err != nil {
		return fmt.Errorf("key retrieval failed: %w", err)
	}

	// DEBUG
	fmt.Printf("Key:               %s\n", key)
	fmt.Printf("Expected Key:      %s\n", wantKey)
	fmt.Printf("Message:           %s\n", message)
	fmt.Printf("Expected Message:  %s\n", wantMessage)

	// Check the result
	if message != wantMessage && key != wantKey {
		return fmt.Errorf("result doesn't match expected value")
	}

	// Alert
	fmt.Println("[i] Challenge passed")

	return nil
}
