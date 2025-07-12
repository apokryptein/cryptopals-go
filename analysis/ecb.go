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

// ByteAtATimeECB implements the ECB byte at a time decryption attack
func ByteAtATimeECB(oracle Oracle, blockSize int, secretLen int) ([]byte, error) {
	// Make a byte slice of size blockSize to track discovered bytes
	recovered := make([]byte, 0, secretLen)

	// Loop - number of times is legnth of appended secret
	for i := range secretLen {
		// Get current block
		blockIndex := i / blockSize

		// Calculate prefix pad length
		padLen := blockSize - 1 - (i % blockSize)

		// Make the basePad
		prefix := bytes.Repeat([]byte{'A'}, padLen)

		// Create current pad by append recovered bytes to prefix
		dictPad := append(append([]byte(nil), prefix...), recovered...)

		// Instiate dictionary to track results
		dictionary := make(map[string]byte)

		// Loop for each possible byte
		for x := range 256 {
			// construct test bytes
			test := append(append([]byte(nil), dictPad...), byte(x))

			// Encrypt test bytes
			ct, _, _ := oracle(test)

			// get applicable block
			baseBlock := ct[blockIndex*blockSize : (blockIndex+1)*blockSize]

			// Add to dictionary for this byte
			dictionary[string(baseBlock)] = byte(x)
		}

		// Get encrypted bytes of raw prefix for compare
		rawCT, _, err := oracle(prefix)
		if err != nil {
			return nil, fmt.Errorf("oracle error: %w", err)
		}

		// Get appilcable block
		realBlk := rawCT[blockIndex*blockSize : (blockIndex+1)*blockSize]

		// See if there's a match in the dictionary
		b, ok := dictionary[string(realBlk)]
		if !ok {
			return nil, fmt.Errorf("could not find byte %d in in dictionary", i)
		}

		// Add to recovered bytes
		recovered = append(recovered, b)
	}

	return recovered, nil
}

// FindRepeatingBlocks finds two adjacent equal blocks of ciphertext
func FindRepeatingBlocks(data []byte, blockSize int) (int, bool) {
	// Get number of blocks
	numBlocks := len(data) / blockSize

	// Iterate over contiguous blocks and check for equality
	for i := range numBlocks {
		block1 := data[i*blockSize : (i+1)*blockSize]
		block2 := data[(i+1)*blockSize : (i+2)*blockSize]

		// Check for equality
		if bytes.Equal(block1, block2) {
			return i, true
		}
	}
	return -1, false
}

// FindAlignment determines the length of prepended random bytes
func FindAlignment(oracle Oracle, blockSize int, marker byte) (padLen int, blockIndex int, err error) {
	// TODO: finish this
	return 0, 0, nil
}
