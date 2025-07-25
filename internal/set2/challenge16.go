package set2

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/apokryptein/cryptopals-go/analysis"
	"github.com/apokryptein/cryptopals-go/crypto"
	"github.com/apokryptein/cryptopals-go/encoding"
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

func Challenge16() (bool, error) {
	// Generate random 16-byte key
	key := make([]byte, aes.BlockSize)
	if _, err := rand.Read(key); err != nil {
		return false, fmt.Errorf("key gen: %w", err)
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return false, fmt.Errorf("IV gen: %w", err)
	}

	// Instantiate oracle
	oracle, err := analysis.NewOracle(analysis.WithMode(analysis.ModeCBC), analysis.WithIv(iv), analysis.WithKey(key))
	if err != nil {
		return false, fmt.Errorf("oracle failed: %w", err)
	}

	// Launch bitflip attack
	modedCT, err := analysis.CBCBitflipAttack(oracle, buildInput, ";admin=true", aes.BlockSize)
	if err != nil {
		return false, fmt.Errorf("bitflip attack failed: %w", err)
	}

	// Decrypt and validate
	ok, err := decryptAndValidate(modedCT, key, iv)
	if err != nil {
		return false, fmt.Errorf("decryption or validation failure: %w", err)
	}

	return ok, nil
}

// runChallenge16 is the runner for the challenge
func runChallenge16() error {
	pass, err := Challenge16()
	if err != nil {
		return fmt.Errorf("[ERR] challenge failed: %w", err)
	}

	// Check if pass
	if pass {
		fmt.Println("[SUCCESS] Challenge passed")
		return nil
	}

	fmt.Println("[FAIL] Challenged failed")
	return nil
}

// buildInput builds the plaintext string returning the string
// and the prefix length
func buildInput(data string) (string, int) {
	// Challenge data
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	// Quote data
	inputQuoted := encoding.QuoteString(data, map[string]string{
		";": "%3B",
		"=": "%3D",
	})

	// Build plaintext
	pt := fmt.Sprintf("%s%s%s", prefix, inputQuoted, suffix)

	return pt, len(prefix)
}

// decryptAndValidate decrypts the ciphertext, parses the decrypted data,
// and valudates the result
func decryptAndValidate(data, key, iv []byte) (bool, error) {
	// Decrypt
	pt, err := crypto.DecryptAESCBC(key, iv, data)
	if err != nil {
		return false, fmt.Errorf("decryption failed: %w", err)
	}

	// Validate PKCS7 padding
	ptUnpadded, err := crypto.ValidatePadding(pt, aes.BlockSize)
	if err != nil {
		return false, fmt.Errorf("padding validation failed: %w", err)
	}

	// Split on ;
	fields := strings.Split(string(ptUnpadded), ";")

	// Convert to map
	keyVals := make(map[string]string)
	for _, field := range fields {
		parts := strings.Split(field, "=")
		if len(parts) == 2 {
			key := parts[0]
			val := encoding.QuoteString(parts[1], map[string]string{
				"%3B": ";",
				"%3D": "=",
				"%20": " ",
			})
			keyVals[key] = val
		}
	}

	// Check for admin=true
	_, ok := keyVals["admin"]

	if ok && keyVals["admin"] == "true" {
		return true, nil
	}

	return false, nil
}
