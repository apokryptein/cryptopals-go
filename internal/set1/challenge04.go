package set1

import (
	"bufio"
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/cryptanalysis"
)

func Challenge04(filePath string) (encData string, decData string, key string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", "", fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var result struct {
		EncryptedData string
		DecryptedData string
		Key           string
	}

	var maxScore float64
	// Instantiate new scanner
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, message, score, err := cryptanalysis.BruteSingleByteXOR(scanner.Text())
		if err != nil {
			return "", "", "", fmt.Errorf("error bruteforcing message: %w", err)
		}

		if score > maxScore {
			maxScore = score
			result.EncryptedData = scanner.Text()
			result.DecryptedData = string(message)
			result.Key = string(key)
		}
	}

	return result.EncryptedData, result.DecryptedData, result.Key, nil
}
