package set2

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/apokryptein/cryptopals-go/internal/analysis"
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

	// Instantiate Oracle
	// oracle, err := analysis.NewOracle(analysis.ModeECB)
	oracle := analysis.NewECBOracle(appendBytes)

	// Get the blocksize
	blockSize, err := analysis.DetectBlocksize(oracle)
	if err != nil {
		return nil, fmt.Errorf("failed to detect blocksize: %w", err)
	}

	// DEBUG
	fmt.Printf("Blocksize: %d\n", blockSize)

	// Encrypt
	ct, _, _ := oracle([]byte(pt))

	// Check to ensure we are using AES ECB
	if ok := analysis.DetectAESECB(ct, blockSize); !ok {
		return nil, fmt.Errorf("oracle is not using AES ECB")
	} else {
		// DEBUG
		fmt.Printf("AES ECB: %v\n", ok)
	}

	// Decrypt using BAAT ECB decryption
	data, err := analysis.ByteAtATimeECB(oracle, blockSize, len(appendBytes))
	if err != nil {
		return nil, fmt.Errorf("byte at a time decryption failed: %w", err)
	}

	// return ct, nil
	return data, nil
}
