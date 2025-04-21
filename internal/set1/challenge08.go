package set1

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

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

		good := crypto.DetectAES_ECB(data, 16)

		if good {
			line = scanner.Text()
		}
	}

	return line, nil
}
