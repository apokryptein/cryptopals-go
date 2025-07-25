package analysis

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	mathrand "math/rand/v2"

	"github.com/apokryptein/cryptopals-go/crypto"
)

// Mode represents the desired AES encryption mode: CBC or ECB
type Mode int

// AES mode enum
const (
	ModeCBC Mode = iota
	ModeECB
	ModeRandom
)

// Oracle is a closure type acting as the blackbox envryption function
type Oracle func(pt []byte) (ct []byte, modeUsed Mode, err error)

// OracleOption represents a functional option for configuring
// an encryption Oracle
type OracleOption func(*OracleConfig)

// OracleConfig represents configuration details for a given oracle
type OracleConfig struct {
	mode         Mode
	randomPrefix bool
	randomSuffix bool
	secretSuffix []byte
	key          []byte
	iv           []byte
}

// WithRandomPrefix is a functional option that sets the
// OracleConfig to use a random prefix
func WithRandomPrefix() OracleOption {
	return func(cfg *OracleConfig) {
		cfg.randomPrefix = true
	}
}

// WithRandomSuffix is a functional option that sets the
// OracleConfig to use a random suffix
func WithRandomSuffix() OracleOption {
	return func(cfg *OracleConfig) {
		cfg.randomSuffix = true
	}
}

// WithSecretSuffix is a functional option that sets the
// OracleConfig to append a secret suffix
func WithSecretSuffix(suffix []byte) OracleOption {
	return func(cfg *OracleConfig) {
		cfg.secretSuffix = suffix
	}
}

// WithMode is a functional option that sets the
// OracleConfig to use the specified AES mode
func WithMode(m Mode) OracleOption {
	return func(cfg *OracleConfig) {
		cfg.mode = m
	}
}

// WithKey is a functional option that sets the
// OracleConfig to use the specified key
func WithKey(key []byte) OracleOption {
	return func(cfg *OracleConfig) {
		cfg.key = key
	}
}

// WithIv is a functional option that sets the
// OracleConfig to use the specified key
func WithIv(iv []byte) OracleOption {
	return func(cfg *OracleConfig) {
		cfg.iv = iv
	}
}

// NewOracle is a constructor for the Oracle type and returns an Oracle that encrypts
// data using either AES ECB or AES CBC
// This oracle prepends and appends random bytes to the plaintext prior to encryption
func NewOracle(opts ...OracleOption) (Oracle, error) {
	// Instantiate OracleConfig
	cfg := &OracleConfig{
		mode: ModeECB, // defaults ECB
	}

	// Apply options
	for _, opt := range opts {
		opt(cfg)
	}

	// Generate random key if none were provided
	if cfg.key == nil {
		// Generate random 16-byte key
		cfg.key = make([]byte, aes.BlockSize)
		if _, err := rand.Read(cfg.key); err != nil {
			return nil, fmt.Errorf("key gen: %w", err)
		}
	}

	// Generate random IV if none were provided (CBC only)
	if cfg.iv == nil && cfg.mode == ModeCBC {
		// Generate random IV
		cfg.iv = make([]byte, aes.BlockSize)
		if _, err := rand.Read(cfg.iv); err != nil {
			return nil, fmt.Errorf("IV gen: %w", err)
		}
	}

	// Create prefix if specified
	var prefix []byte
	if cfg.randomPrefix {
		// Random bytes for preprend and append to plaintext
		prefixLen := mathrand.IntN(6) + 5 // random int 5-10
		prefix = make([]byte, prefixLen)
		// appBytes := make([]byte, randByteNum)
		if _, err := rand.Read(prefix); err != nil {
			return nil, fmt.Errorf("prefix gen: %w", err)
		}

	}

	// Create suffix if specified
	var suffix []byte
	if cfg.randomSuffix {
		// Random bytes for preprend and append to plaintext
		suffixLen := mathrand.IntN(6) + 5 // random int 5-10
		suffix = make([]byte, suffixLen)
		// appBytes := make([]byte, randByteNum)
		if _, err := rand.Read(suffix); err != nil {
			return nil, fmt.Errorf("prefix gen: %w", err)
		}

	}

	// Return an Oracle closure
	return func(plaintext []byte) ([]byte, Mode, error) {
		// Generate new plaintext slice
		ptBytes := make([]byte, 0, len(prefix)+len(plaintext)+len(suffix)+len(cfg.secretSuffix))
		ptBytes = append(ptBytes, prefix...)
		ptBytes = append(ptBytes, plaintext...)
		ptBytes = append(ptBytes, suffix...)
		ptBytes = append(ptBytes, cfg.secretSuffix...)

		// Logic to handle random mode selection for ModeRandom
		chosenMode := cfg.mode
		if cfg.mode == ModeRandom {
			// Random choice of 0 or 1 to determine AES ECB/CBC
			selection := mathrand.IntN(2)
			if selection == 0 {
				chosenMode = ModeECB
			} else {
				chosenMode = ModeCBC
			}
		}

		// Check for IV in case of random mode
		if chosenMode == ModeCBC && cfg.iv == nil {
			// Generate random IV
			cfg.iv = make([]byte, aes.BlockSize)
			if _, err := rand.Read(cfg.iv); err != nil {
				return nil, 0, fmt.Errorf("IV gen: %w", err)
			}
		}

		// Pad plaintext
		ptPadded, err := crypto.PaddingPKCS7(ptBytes, aes.BlockSize)
		if err != nil {
			return nil, 0, fmt.Errorf("padding failed: %w", err)
		}

		// Check mode and set encryptor
		var encryptor func([]byte, []byte, []byte) ([]byte, error)
		switch chosenMode {
		case ModeCBC:
			encryptor = cbcEncrypt
		case ModeECB:
			encryptor = func(k, _, ptBytes []byte) ([]byte, error) {
				return ecbEncrypt(k, ptBytes)
			}
		default:
			return nil, 0, fmt.Errorf("unsupported mode: %v", chosenMode)
		}

		// Encrypt using selected encryptor
		ciphertext, err := encryptor(cfg.key, cfg.iv, ptPadded)
		return ciphertext, chosenMode, err
	}, nil
}

// WrapOracle wraps a given oracle to prepend determined pad length to account
// for random prepended bytes: used in Challenge 14
func WrapOracle(original Oracle, padLen, blockIndex, blockSize int) Oracle {
	return func(pt []byte) ([]byte, Mode, error) {
		// Prepend alignment pad
		alignedInput := append(bytes.Repeat([]byte{'A'}, padLen), pt...)

		// Call original oracle
		ct, mode, err := original(alignedInput)
		if err != nil {
			return nil, mode, fmt.Errorf("oracle failed: %w", err)
		}

		// Skip blocks containing random prefix
		start := blockIndex * blockSize
		if len(ct) < start {
			return nil, mode, fmt.Errorf("ciphertext too short after alignment")
		}

		// return aligned slice
		alignedCt := ct[start:]
		return alignedCt, mode, nil
	}
}

// String is a helper function that returns the associated string for a given Mode
func (m Mode) String() string {
	return [...]string{"ModeCBC", "ModeECB"}[m]
}

// AES CBC helper function
func cbcEncrypt(key, iv, pt []byte) ([]byte, error) {
	return crypto.EncryptAESCBC(key, iv, pt)
}

// AES ECB helper function
func ecbEncrypt(key, pt []byte) ([]byte, error) {
	return crypto.EncryptAESECB(key, pt)
}
