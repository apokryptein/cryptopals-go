package set1

import (
	"encoding/hex"
	"fmt"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

func Challenge05(plaintext string, key string) (hexString string, err error) {
	encData, err := crypto.RepeatingKeyXOR([]byte(plaintext), []byte(key))
	if err != nil {
		return "", fmt.Errorf("error encrypting data using RepeatingKeyXOR: %w", err)
	}

	return hex.EncodeToString(encData), nil
}
