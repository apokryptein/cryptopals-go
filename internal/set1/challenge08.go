package set1

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/analysis"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         1,
		Number:      8,
		Name:        "Detect AES in ECB mode",
		Description: "Function to detect whether ciphertext has been encrypted using AES in ECB mode",
		Implemented: true,
		Run:         runChallenge08,
	})
}

func Challenge08(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var line string

	for scanner.Scan() {
		data, err := hex.DecodeString(scanner.Text())
		if err != nil {
			return "", fmt.Errorf("error decoding string: %w", err)
		}

		good := analysis.DetectAESECB(data, 16)

		if good {
			line = scanner.Text()
		}
	}

	return line, nil
}

func runChallenge08() error {
	// Data
	wantResult := "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"

	// Run challenge
	result, err := Challenge08("./testdata/set1-challenge08_data.txt")
	if err != nil {
		return fmt.Errorf("detection failed: %w", err)
	}

	// DEBUG
	fmt.Printf("Detected:  %s\n", result)
	fmt.Printf("Expected:   %s\n", wantResult)

	// Check result
	if result != wantResult {
		return fmt.Errorf("result doesn't match expected value")
	}

	// Alert
	fmt.Println("[i] Challenge passed")

	return nil
}
