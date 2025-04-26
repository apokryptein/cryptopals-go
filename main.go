package main

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/apokryptein/cryptopals-go/internal/cryptanalysis"
)

func main() {
	const numTests = 1000
	var correctDetections int

	for range numTests {
		pt := bytes.Repeat([]byte("A"), 128)

		ct, mode, _ := cryptanalysis.EncryptionOracle([]byte(pt))
		result := cryptanalysis.DetectAES_ECB(ct, aes.BlockSize)

		if (mode == "ECB" && result) || (mode == "CBC" && !result) {
			correctDetections++
		}
	}

	fmt.Printf("Accuracy: %d/%d (%.2f%%)\n", correctDetections, numTests, (float64(correctDetections)/float64(numTests))*100)
}
