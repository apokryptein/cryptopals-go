package cryptanalysis

import (
	"fmt"
	"slices"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

func BreakRepeatingKeyXOR(ciphertext []byte) (key []byte, plaintext []byte, err error) {
	const maxKeysize = 40
	smallestScore := 0.0
	var keySize int
	var keyBytes []byte
	var cipherChunks [][]byte

	for k := 2; k <= maxKeysize; k++ {
		pairs := 10
		var distSum float64

		for i := range pairs {
			b1 := ciphertext[i*k : k*(i+1)]
			b2 := ciphertext[k*(i+1) : (i+2)*k]
			hDist, err := HammingDistance(b1, b2)
			if err != nil {
				return nil, nil, fmt.Errorf("BreakRepeatingKeyXOR: %w", err)
			}

			distSum += NormalizeDistance(hDist, k)
		}

		normDist := distSum / float64(pairs)

		if k == 2 {
			smallestScore = normDist
			keySize = k
			continue
		}

		if normDist < smallestScore {
			smallestScore, keySize = normDist, k
		}
	}

	// Split ciphertext into keysize slice and append to [][]byte
	for chunk := range slices.Chunk(ciphertext, keySize) {
		cipherChunks = append(cipherChunks, chunk)
	}

	for i := range keySize {
		keySlice := collectFromMatrix(i, cipherChunks)
		keyByte, _, _, _ := BruteSingleByteXOR(keySlice)
		keyBytes = append(keyBytes, keyByte)
	}

	plaintext, err = crypto.RepeatingKeyXOR(ciphertext, keyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("BreakRepeatingKeyXOR: %w", err)
	}

	return keyBytes, plaintext, nil
}

func collectFromMatrix(n int, matrix [][]byte) []byte {
	// out := make([]byte, len(matrix))
	var out []byte
	for _, row := range matrix {
		// account of shortened last row
		if n < len(row) {
			out = append(out, row[n])
		}
	}

	return out
}
