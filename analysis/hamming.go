package analysis

import (
	"fmt"
	"math/bits"
)

// HammingDistance calculates the hamming distance of two byte slices
func HammingDistance(b1, b2 []byte) (int, error) {
	// Ensure byte slices are of equal length
	if len(b1) != len(b2) {
		return 0, fmt.Errorf("buffer lengths differ")
	}

	// Instantiate counter
	hammingDistance := 0

	// Iterate ove length of slice, xor, compare
	for i := range b1 {
		hammingDistance += bits.OnesCount8(b1[i] ^ b2[i])
	}

	return hammingDistance, nil
}

// NormalizeDistance normalizes HammingDistance
func NormalizeDistance(distance, keySize int) float64 {
	return float64(distance) / float64(keySize)
}
