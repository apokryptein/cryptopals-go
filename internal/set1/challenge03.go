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
		// Run:         runChallenge03,
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
