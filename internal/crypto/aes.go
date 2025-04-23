package crypto

import (
	"crypto/aes"
	"crypto/cipher"
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

func EncryptAES_ECB(key, data []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating new cipher: %w", err)
	}

	ptBytes := make([]byte, len(data))

	for i := 0; i < len(data); i += len(key) {
		cipher.Encrypt(ptBytes[i:(i+len(key))], data[i:(i+len(key))])
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

func DecryptAES_CBC(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating new cipher: %w", err)
	}

	// Check ciphertext is of sufficient length
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Ensure ciphertext is multiple of blocksize
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of blocksize")
	}

	iv = data[:aes.BlockSize]
	// data = data[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(data, data)

	return data, nil
}
