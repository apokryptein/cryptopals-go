package set2

import (
	"crypto/aes"
	"fmt"

	"github.com/apokryptein/cryptopals-go/analysis"
	"github.com/apokryptein/cryptopals-go/crypto"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         2,
		Number:      16,
		Name:        "CBC bit flipping attacks",
		Description: "",
		Implemented: true,
		Run:         runChallenge16,
	})
}

func Challenge16() error {
	ct, err := buildCiphertext("testdata")
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	// DEBUG
	fmt.Printf("[DEBUG] Ciphertext: %v\n", ct)

	return nil
}

func runChallenge16() error {
	return Challenge16()
}

func buildCiphertext(data string) ([]byte, error) {
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	// TODO: quote out ';' and '=' characters
	// Read the exercise more carefully:
	// it may be more prudent to use direct calls to the CBC encryption function
	// instead of using an oracle to allow for easier decryption as the key will be
	// hidden in the oracle.

	pt := fmt.Sprintf("%s%s%s", prefix, data, suffix)
	paddedPT, err := crypto.PaddingPKCS7([]byte(pt), aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("[ERR] padding failure: %w", err)
	}

	// DEBUG
	fmt.Printf("[DEBUG] Plaintext: %s\n", paddedPT)

	oracle, err := analysis.NewOracle(analysis.WithMode(analysis.ModeCBC))
	if err != nil {
		return nil, fmt.Errorf("[ERR] oracle instantiation failed: %w", err)
	}

	ct, _, err := oracle([]byte(pt))
	if err != nil {
		return nil, fmt.Errorf("[ERR] oracle failed: %w", err)
	}

	return ct, nil
}
