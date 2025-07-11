package set1

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/apokryptein/cryptopals-go/analysis"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         1,
		Number:      6,
		Name:        "Break repeating-key XOR",
		Description: "Implementation of breaking repeating-key XOR",
		Implemented: true,
		// Run:         runChallenge06,
	})
}

func Challenge06(filePath string) (key string, plaintext string, err error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", fmt.Errorf("error reading file: %w", err)
	}

	cleanData := strings.ReplaceAll(string(data), "\n", "")
	decodedData, err := base64.StdEncoding.DecodeString(cleanData)
	if err != nil {
		return "", "", fmt.Errorf("error decoding base64 string: %w", err)
	}

	keyBytes, pTextBytes, err := analysis.BreakRepeatingKeyXOR(decodedData)
	if err != nil {
		return "", "", fmt.Errorf("Challenge06: %v", err)
	}

	return string(keyBytes), string(pTextBytes), nil
}
