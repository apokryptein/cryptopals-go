// Package cryptanalysis contains function implementing various cryptanalysis techniques
package cryptanalysis

// DetectAES_ECB detects whether ciphertext has been encrypted with AES ECB
func DetectAES_ECB(data []byte, blockSize int) bool {
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

func DetectBlocksize() {}
