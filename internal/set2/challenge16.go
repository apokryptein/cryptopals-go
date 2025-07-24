package set2

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"strings"

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

	// Build and encrypt
	ct, err := buildCiphertext("test;admin=true", key, iv)
	if err != nil {
		return false, fmt.Errorf("%w", err)
	}

	// Decrypt and validate
	_, err = decryptAndValidate(ct, key, iv)
	if err != nil {
		return false, fmt.Errorf("decryption or validation failure: %w", err)
	}

	return true, nil
}

// runChallenge16 is the runner for the challenge
func runChallenge16() error {
	pass, err := Challenge16()
	if err != nil {
		return fmt.Errorf("[ERR] challenge failed: %w", err)
	}

	if pass {
		fmt.Println("[i] Challenge passed")
	}

	return nil
}

// buildCiphertext builds the plaintext, encodes it as directed, and encrypts it
// using AES CBC mode
func buildCiphertext(data string, key []byte, iv []byte) ([]byte, error) {
	// Challenge data
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"

	// Build plaintext
	pt := fmt.Sprintf("%s%s%s", prefix, data, suffix)

	ptQuoted := encoding.QuoteString(pt, map[string]string{
		";": "%3B",
		"=": "%3D",
	})

	// Pad the plaintext
	ptPadded, err := crypto.PaddingPKCS7([]byte(ptQuoted), aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("[ERR] padding failure: %w", err)
	}

	// DEBUG
	fmt.Printf("[DEBUG] Plaintext: %s\n", ptPadded)

	// Encrypt
	ct, err := crypto.EncryptAESCBC(key, iv, ptPadded)
	if err != nil {
		return nil, fmt.Errorf("[ERR] oracle failed: %w", err)
	}

	return ct, nil
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

	// Remove URL encoding
	ptUnquoted := encoding.QuoteString(string(ptUnpadded), map[string]string{
		"%3B": ";",
		"%3D": "=",
		"%20": " ",
	})

	// DEBUG
	fmt.Printf("[DEBUG] Unquoted PT: %s\n", ptUnquoted)

	// Split on ;
	fields := strings.Split(ptUnquoted, ";")

	// Convert to map
	keyVals := make(map[string]string)
	for _, field := range fields {
		vals := strings.Split(field, "=")
		keyVals[vals[0]] = vals[1]
	}

	// DEBUG
	fmt.Printf("[DEBUG] Data: %v\n", keyVals)

	// Check for admin=true
	_, ok := keyVals["admin"]

	if ok && keyVals["admin"] == "true" {
		return true, nil
	}

	return false, nil
}
