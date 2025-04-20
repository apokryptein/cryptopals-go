package set1

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

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

	// TODO: complete challenge
	fmt.Println(string(decodedData))

	return "", "", nil
}
