package set1

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

func Challenge07(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("error reading file: %w", err)
	}

	cleanData := strings.ReplaceAll(string(data), "\n", "")
	decodedData, err := base64.StdEncoding.DecodeString(cleanData)
	if err != nil {
		return "", fmt.Errorf("error decoding data: %w", err)
	}

	key := "YELLOW SUBMARINE"

	pyBytes, _ := crypto.DecryptAES([]byte(key), decodedData)

	return string(pyBytes), nil
}
