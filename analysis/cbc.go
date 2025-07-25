package analysis

import (
	"bytes"
	"fmt"
)

// CBCBitflipAttack implements the AES CBC bitflip attackas per
func CBCBitflipAttack(oracle Oracle, buildFunc func(string) (string, int), target string, blockSize int) ([]byte, error) {
	// Build input
	placeHolder := bytes.Repeat([]byte{'X'}, len(target))

	// Build plaintext string
	pt, prefixLen := buildFunc(string(placeHolder))

	// Calculate positions
	injectionPoint := prefixLen
	targetBlock := injectionPoint / blockSize

	// Encrypt
	ct, _, err := oracle([]byte(pt))
	if err != nil {
		return nil, fmt.Errorf("oracle failed: %w", err)
	}

	for i := range len(target) {
		// Update cursor
		pos := injectionPoint + i

		// Get target byte
		targetByte := pos % blockSize

		// Get the block we want to control
		controllingBlock := targetBlock - 1

		// Flip bits
		// CT[target byte of controlling block] ^= (X ^ wanted[i])
		ct[controllingBlock*blockSize+targetByte] ^= placeHolder[i] ^ target[i]
	}

	return ct, nil
}
