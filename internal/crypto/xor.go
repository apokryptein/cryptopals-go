package crypto

import (
	"fmt"
)

// XORs a buffer with a single byte key
func SingleByteXOR(message []byte, key byte) ([]byte, error) {
	xorResult := make([]byte, len(message))

	for _, b := range message {
		xorResult = append(xorResult, b^key)
	}

	return xorResult, nil
}

// XORs a buffer using a repating key
func RepeatingKeyXOR(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key must not be empty")
	}

	// Create result byte slice
	xorResult := make([]byte, len(plaintext))

	// Iterate and xor
	for i, b := range plaintext {
		xorResult[i] = b ^ key[i%len(key)]
	}

	// Convert to hex string and return
	return xorResult, nil
}
