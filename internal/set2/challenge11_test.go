package set2_test

import (
	"bytes"
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func TestChallenge11(t *testing.T) {
	const numTests = 1000
	var correctDetections int

	for range numTests {
		// Generate repeated plaintext
		pt := bytes.Repeat([]byte("A"), 128)

		mode, result, err := set2.Challenge11(pt)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Evaluate result
		if (mode == "ECB" && result) || (mode == "CBC" && !result) {
			correctDetections++
		} else {
			t.Logf("Misdetection: mode=%s, detectedECB=%v", mode, result)
		}
	}

	successRate := float64(correctDetections) / float64(numTests)
	t.Logf("Success rate: %.2f%%", successRate*100)

	if successRate < 0.90 {
		t.Errorf("Detection accuracy too low:  %.2f%%", successRate*100)
	}
}
