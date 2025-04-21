package crypto

import (
	"crypto/aes"
	"fmt"
)

func DecryptAES_ECB(key, data []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating new cipher: %w", err)
	}

	ptBytes := make([]byte, len(data))

	for i := 0; i < len(data); i += len(key) {
		cipher.Decrypt(ptBytes[i:(i+len(key))], data[i:(i+len(key))])
	}

	return ptBytes, nil
}

func DetectAES_ECB(data []byte, blockSize int) bool {
	if len(data) < 2*blockSize {
		return false
	}

	nBlocks := len(data) / blockSize

	seen := make(map[[16]byte]struct{}, nBlocks)

	for i := range nBlocks {
		var block [16]byte

		copy(block[:], data[i*blockSize:(i+1)*blockSize])

		if _, dup := seen[block]; dup {
			return true
		}
		seen[block] = struct{}{}
	}
	return false
}
