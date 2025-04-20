package set1

import (
	"fmt"

	cryptanalysis "github.com/apokryptein/cryptopals-go/internal/cryptanalysis"
)

func Challenge03(messageEnc string) (key, message string, score float64, err error) {
	keyByte, messageBytes, score, err := cryptanalysis.BruteSingleByteXOR(messageEnc)
	if err != nil {
		return "", "", 0, fmt.Errorf("error bruteforcing message: %w", err)
	}

	return string(keyByte), string(messageBytes), score, nil
}
