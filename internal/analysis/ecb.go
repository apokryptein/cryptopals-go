// Package analysis contains function implementing various cryptanalysis techniques
package analysis

import (
	"bytes"
	"fmt"
)

// DetectAESECB detects whether ciphertext has been encrypted with AES ECB
func DetectAESECB(data []byte, blockSize int) bool {
	// Must have at least two blocks for validation
	if len(data) < 2*blockSize {
		return false
	}

	// Numnber of blocks in ciphertext
	nBlocks := len(data) / blockSize

	// Map storing whether a previous block has been seen
	seen := make(map[[16]byte]struct{}, nBlocks)

	// Iterate through blocks to check for duplicates
	for i := range nBlocks {
		var block [16]byte

		copy(block[:], data[i*blockSize:(i+1)*blockSize])

		if _, dup := seen[block]; dup {
			return true
		}
		seen[block] = struct{}{}
	}
	return false
}

// DetectBlocksize returns the blocksize of a given encryption algorithm
// in the provided oracle
func DetectBlocksize(oracle Oracle) (blockSize int, err error) {
	// Encrypt with 0 bytes for initial length
	initialCT, _, err := oracle([]byte{})
	if err != nil {
		return 0, fmt.Errorf("oracle encryption failure: %w", err)
	}

	// Get initial length using 0 bytes
	initialLen := len(initialCT)

	// Generate pt of up to 256 bytes if needed
	for i := range 256 {
		// Append i bytes
		pt := bytes.Repeat([]byte{'A'}, i)

		// Encrypt
		ct, _, err := oracle(pt)
		if err != nil {
			return 0, fmt.Errorf("oracle failed at %d bytes: %w", i, err)
		}

		// Check legnth against initialLen
		if newLen := len(ct); newLen > initialLen {
			return newLen - initialLen, nil
		}
	}

	return 0, fmt.Errorf("failed to detect blocksize after 256 bytes")
}
