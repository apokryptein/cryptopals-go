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
		Run:         runChallenge05,
	})
}

func Challenge05(plaintext string, key string) (hexString string, err error) {
	encData, err := crypto.RepeatingKeyXOR([]byte(plaintext), []byte(key))
	if err != nil {
		return "", fmt.Errorf("error encrypting data using RepeatingKeyXOR: %w", err)
	}

	return hex.EncodeToString(encData), nil
}

func runChallenge05() error {
	data := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	wantResult := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	// Run challenge
	encData, err := Challenge05(data, key)
	if err != nil {
		return fmt.Errorf("XOR failed: %w", err)
	}

	// DEBUG
	fmt.Printf("Encrypted:  %s\n", encData)
	fmt.Printf("Expected:   %s\n", wantResult)

	// Check result
	if encData != wantResult {
		return fmt.Errorf("result doesn't match expected value")
	}

	// Alert
	fmt.Println("[i] Challenge passed")

	return nil
}
