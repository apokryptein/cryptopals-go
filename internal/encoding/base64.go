package encoding

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Take a hex string and returns a base64 encoded string
func HexToBase64(hexString string) (string, error) {
	hexBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return "", fmt.Errorf("error decoding hex string to bytes: %w", err)
	}

	return base64.StdEncoding.EncodeToString(hexBytes), nil
}
