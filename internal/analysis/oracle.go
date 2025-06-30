package analysis

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	mathrand "math/rand/v2"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

// Mode represents the desired AES encryption mode: CBC or ECB
type Mode int

const (
	ModeCBC Mode = iota
	ModeECB
	ModeRandom
)

// Oracle is a closure type acting as the blackbox envryption function
type Oracle func(pt []byte) (ct []byte, modeUsed Mode, err error)

// NewOracle is a constructor for the Oracle type and returns an Oracle that encrypts
// data using either AES ECB or AES CBC
func NewOracle(m Mode) (Oracle, error) {
	// Generate random 16-byte key
	key := make([]byte, aes.BlockSize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("key gen: %w", err)
	}

	// Random bytes for preprend and append to plaintext
	randByteNum := mathrand.IntN(6) + 5 // random int 5-10
	preBytes := make([]byte, randByteNum)
	appBytes := make([]byte, randByteNum)
	if _, err := rand.Read(preBytes); err != nil {
		return nil, fmt.Errorf("prefix gen: %w", err)
	}
	if _, err := rand.Read(appBytes); err != nil {
		return nil, fmt.Errorf("suffix gen: %w", err)
	}

	// Return an Oracle closure
	return func(plaintext []byte) ([]byte, Mode, error) {
		// Generate new plaintext slice
		ptBytes := make([]byte, 0, len(plaintext)+2*randByteNum)
		ptBytes = append(ptBytes, preBytes...)
		ptBytes = append(ptBytes, plaintext...)
		ptBytes = append(ptBytes, appBytes...)

		// Logic to handle random mode selection for ModeRandom
		chosenMode := m
		if m == ModeRandom {
			// Random choice of 0 or 1 to determine AES ECB/CBC
			selection := mathrand.IntN(2)
			if selection == 0 {
				chosenMode = ModeECB
			} else {
				chosenMode = ModeCBC
			}
		}

		// Check mode and set encryptor
		var encryptor func([]byte, []byte) ([]byte, error)
		switch chosenMode {
		case ModeCBC:
			encryptor = cbcEncrypt
		case ModeECB:
			encryptor = ecbEncrypt
		default:
			return nil, 0, fmt.Errorf("unsupported mode: %v", chosenMode)
		}

		// Encrypt using selected encryptor
		ciphertext, err := encryptor(key, ptBytes)
		return ciphertext, chosenMode, err
	}, nil
}

// String is a helper function that returns the associated string for a given Mode
func (m Mode) String() string {
	return [...]string{"ModeCBC", "ModeECB"}[m]
}

// AES CBC helper function
func cbcEncrypt(key, pt []byte) ([]byte, error) {
	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("IV gen: %w", err)
	}

	return crypto.EncryptAESCBC(key, iv, pt)
}

// AES ECB helper function
func ecbEncrypt(key, pt []byte) ([]byte, error) {
	return crypto.EncryptAESECB(key, pt)
}
