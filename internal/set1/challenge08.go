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
		// Run:         runChallenge08,
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
