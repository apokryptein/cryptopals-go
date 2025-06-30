package analysis

import (
	"fmt"
	"strings"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

// BruteSingleByteXOR bruteforces a message enncoded/encrypted using single byte XOR using frequency analysis
func BruteSingleByteXOR(message []byte) (goodKey byte, goodMessage []byte, goodScore float64, err error) {
	// Score variable
	var maxScore float64 = -1

	// Iterate over all single byte key values
	for k := range 256 {
		// Convert key to byte
		key := byte(k)

		// Get XOR'd value
		xorResult, err := crypto.SingleByteXOR(message, key)
		if err != nil {
			return 0, nil, 0, fmt.Errorf("error xoring message: %w", err)
		}

		// Score result
		score, err := ScoreEnglish(xorResult)
		if err != nil {
			return 0, nil, 0, fmt.Errorf("error scoring english: %w", err)
		}

		// If better score, assign everything
		if score > maxScore {
			maxScore = score
			goodKey = key
			goodMessage = xorResult
			goodScore = score
		}
	}
	return
}

// ScoreEnglish scores a phrase based on letter frequencies in English
func ScoreEnglish(message []byte) (float64, error) {
	// Letter frequencies: https://www.programming-algorithms.net/article/40379/Letter-frequency-English
	englishFrequencies := map[rune]float64{
		'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253,
		'e': 12.702, 'f': 2.228, 'g': 2.015, 'h': 6.094,
		'i': 6.966, 'j': 0.153, 'k': 0.772, 'l': 4.025,
		'm': 2.406, 'n': 6.749, 'o': 7.507, 'p': 1.929,
		'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
		'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150,
		'y': 1.974, 'z': 0.074, ' ': 13.000,
	}

	// Declare necessary variables
	letterCounts := make(map[rune]int)
	var score float64

	// Count occurrence of each letter in phrase
	for _, r := range strings.ToLower(string(message)) {
		if _, ok := englishFrequencies[r]; ok {
			letterCounts[r]++
		}
	}

	// Calculate score based on letter counts and frequency
	for r, count := range letterCounts {
		freq := englishFrequencies[r]
		score += float64(count) * freq
	}

	return score, nil
}
