package crypto

import (
	"crypto/aes"
	"fmt"

	"github.com/apokryptein/cryptopals-go/internal/encoding"
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
	var err error

	// Check ciphertext is of sufficient length
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Ensure ciphertext is multiple of blocksize
	// If not, pad with PKCS7
	if len(data)%aes.BlockSize != 0 {
		data, err = PaddingPKCS7(data, aes.BlockSize)
		if err != nil {
			return nil, fmt.Errorf("error padding data: %w", err)
		}
	}

	previousBlock := iv
	plaintext := make([]byte, len(data))

	for i := 0; i < len(data); i += aes.BlockSize {
		// Get current block
		currentBlock := data[i : i+aes.BlockSize]

		// Decrypt current block
		decData, err := DecryptAES_ECB(key, currentBlock)
		if err != nil {
			return nil, fmt.Errorf("error decrypting block: %w", err)
		}

		// XOR with encrypted previous block (or IV) to get plaintext
		p, err := encoding.FixedXOR(decData, previousBlock)
		if err != nil {
			return nil, fmt.Errorf("error xoring block: %w", err)
		}

		// previousBlock is current endcrypted block
		previousBlock = currentBlock

		// Append decrypted block to plaintext
		plaintext = append(plaintext, p...)
	}

	return plaintext, nil
}
