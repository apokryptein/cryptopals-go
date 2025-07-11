package set1

import (
	"encoding/hex"
	"fmt"

	"github.com/apokryptein/cryptopals-go/crypto"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         1,
		Number:      5,
		Name:        "Repeating-key XOR",
		Description: "Implementation of repeating-key XOR",
		Implemented: true,
		// Run:         runChallenge05,
	})
}

func Challenge05(plaintext string, key string) (hexString string, err error) {
	encData, err := crypto.RepeatingKeyXOR([]byte(plaintext), []byte(key))
	if err != nil {
		return "", fmt.Errorf("error encrypting data using RepeatingKeyXOR: %w", err)
	}

	return hex.EncodeToString(encData), nil
}
