package set2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/apokryptein/cryptopals-go/crypto"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         2,
		Number:      10,
		Name:        "Implement CBC mode",
		Description: "Implement AES using Cipher Block Chaining (CBC) mode",
		Implemented: true,
		// Run:         runChallenge10,
	})
}

func Challenge10(filePath string) ([]byte, error) {
	key := "YELLOW SUBMARINE"

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}

	cleanData := strings.ReplaceAll(string(data), "\n", "")
	decData, err := base64.StdEncoding.DecodeString(cleanData)
	if err != nil {
		return nil, fmt.Errorf("error decoding hex: %w", err)
	}

	// Manually set IV to 16 null bytes as per challenge instructions
	iv := bytes.Repeat([]byte("0"), 16)

	pt, err := crypto.DecryptAESCBC([]byte(key), iv, []byte(decData))
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return pt, nil
}
