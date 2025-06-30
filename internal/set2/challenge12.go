package set2

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/apokryptein/cryptopals-go/internal/cryptanalysis"
)

func Challenge12() ([]byte, error) {
	// Inital data of just A bytes
	pt := bytes.Repeat([]byte("A"), 128)

	// base64 decode append data
	appendData := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	appendBytes, err := base64.StdEncoding.DecodeString(appendData)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode append data: %w", err)
	}

	// append data to initial buffer
	pt = append(pt, appendBytes...)

	// Encrypt it -> ECB
	ct, _, _ := cryptanalysis.EncryptionOracle([]byte(pt), cryptanalysis.ECB)

	return ct, nil
}
