package encoding

import (
	"encoding/hex"
	"fmt"
)

// XORs two buffer of equal length
func FixedXOR(buf1 string, buf2 string) (string, error) {
	if len(buf1) != len(buf2) {
		return "", fmt.Errorf("buffer lengths differ")
	}

	buf1Bytes, err := hex.DecodeString(buf1)
	if err != nil {
		return "", fmt.Errorf("error decoding hex: %w", err)
	}

	buf2Bytes, err := hex.DecodeString(buf2)
	if err != nil {
		return "", fmt.Errorf("error decoding hex: %w", err)
	}

	var xorResult []byte
	for i := range buf1Bytes {
		xorResult = append(xorResult, buf1Bytes[i]^buf2Bytes[i])
	}

	return hex.EncodeToString(xorResult), nil
}

// XORs a buffer with a single byte key
func FixedSingleByteXOR(message []byte, key byte) ([]byte, error) {
	xorResult := make([]byte, len(message))

	for _, b := range message {
		xorResult = append(xorResult, b^key)
	}

	return xorResult, nil
}
