package cryptanalysis

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	mathrand "math/rand/v2"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

// Encrypts data using either AES ECB or AES CBC
// randomly selected
func EncryptionOracle(plaintext []byte) ([]byte, error) {
	// Generate random 16-byte key
	key := make([]byte, aes.BlockSize)
	rand.Read(key)

	// Random bytes for preprend and append to plaintext
	randByteNum := mathrand.IntN(6) + 5 // random int 5-10
	preBytes := make([]byte, randByteNum)
	appBytes := make([]byte, randByteNum)
	rand.Read(preBytes)
	rand.Read(appBytes)

	// Generate new plaintext slice
	ptBytes := make([]byte, 0, len(plaintext)+2*randByteNum)
	ptBytes = append(ptBytes, preBytes...)
	ptBytes = append(ptBytes, plaintext...)
	ptBytes = append(ptBytes, appBytes...)

	// Random choice of 1 or 2 to determine AES ECB/CBC
	selection := mathrand.IntN(2) + 1 // random int 1-2

	var ciphertext []byte
	var err error

	if selection == 1 {
		fmt.Println("CBC")
		// Generate random IV
		iv := make([]byte, aes.BlockSize)
		rand.Read(iv)

		ciphertext, err = crypto.EncryptAES_CBC(key, iv, ptBytes)
		if err != nil {
			return nil, fmt.Errorf("error during AES-CBC encryption: %w", err)
		}
	} else {
		fmt.Println("ECB")
		ciphertext, err = crypto.EncryptAES_ECB(key, ptBytes)
		if err != nil {
			return nil, fmt.Errorf("error during AES-ECB encryption: %w", err)
		}
	}

	return ciphertext, nil
}
