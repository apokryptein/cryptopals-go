// Package crypto implements various encryption algorithms and helper functions
package crypto

import (
	"crypto/aes"
	"fmt"

	"github.com/apokryptein/cryptopals-go/internal/encoding"
)

// DecryptAESECB implements AES Electronic Code Block (ECB) decryption
func DecryptAESECB(key, data []byte) ([]byte, error) {
	// Ensure ciphertext is multiple of blocksize
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not multiple of blocksize")
	}

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

// EncryptAESECB implements AES Electronic Code Block (ECB) encryption
func EncryptAESECB(key, data []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating new cipher: %w", err)
	}

	// Ensure ciphertext is multiple of blocksize
	// If not, pad with PKCS7
	if len(data)%aes.BlockSize != 0 {
		data, err = PaddingPKCS7(data, aes.BlockSize)
		if err != nil {
			return nil, fmt.Errorf("error padding data: %w", err)
		}
	}

	ptBytes := make([]byte, len(data))

	for i := 0; i < len(data); i += len(key) {
		cipher.Encrypt(ptBytes[i:(i+len(key))], data[i:(i+len(key))])
	}

	return ptBytes, nil
}

// DecryptAESCBC impelements AES Cipher Block Chaining (CBC) Decryption
// Employs DecryptAESECB function
func DecryptAESCBC(key, iv, data []byte) ([]byte, error) {
	// Check ciphertext is of sufficient length
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Ensure ciphertext is multiple of blocksize
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not multiple of blocksize")
	}

	// Initial previous block is IV
	previousBlock := iv

	// Instantiate slice to house plaintext
	plaintext := make([]byte, 0, len(data))

	for i := 0; i < len(data); i += aes.BlockSize {
		// Get current block
		currentBlock := data[i : i+aes.BlockSize]

		// Decrypt current block
		decData, err := DecryptAESECB(key, currentBlock)
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

// EncryptAESCBC impelements AES Cipher Block Chaining (CBC) Encryption
// Employs EncryptAESECB function
func EncryptAESCBC(key, iv, data []byte) ([]byte, error) {
	var err error

	// Ensure ciphertext is multiple of blocksize
	// If not, pad with PKCS7
	if len(data)%aes.BlockSize != 0 {
		data, err = PaddingPKCS7(data, aes.BlockSize)
		if err != nil {
			return nil, fmt.Errorf("error padding data: %w", err)
		}
	}

	// Initial previous block is IV
	previousBlock := iv

	// Instantiate slice to house ciphertext
	ciphertext := make([]byte, 0, len(data))

	for i := 0; i < len(data); i += aes.BlockSize {
		// Get current block
		currentBlock := data[i : i+aes.BlockSize]

		xBlock, err := encoding.FixedXOR(currentBlock, previousBlock)
		if err != nil {
			return nil, fmt.Errorf("error xoring block: %w", err)
		}

		// Encrypt current block
		encData, err := EncryptAESECB(key, xBlock)
		if err != nil {
			return nil, fmt.Errorf("error decrypting block: %w", err)
		}

		// previousBlock is current endcrypted block
		previousBlock = encData

		// Append encrypted block to ciphertext
		ciphertext = append(ciphertext, encData...)
	}

	return ciphertext, nil
}
