package set2

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/apokryptein/cryptopals-go/analysis"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         2,
		Number:      14,
		Name:        "Byte-at-a-time ECB decryption (harder)",
		Description: "Decrypt an unknown appended string using byte-at-a-time ECB decryption when random bytes have been prepended to the plaintext",
		Implemented: true,
		Run:         runChallenge14,
	})
}

func Challenge14() ([]byte, error) {
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
	oracle, err := analysis.NewOracle(
		analysis.WithMode(analysis.ModeECB),
		analysis.WithRandomPrefix(),
		analysis.WithSecretSuffix(appendBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new oracle: %w", err)
	}

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

	// Find alignment to account for random prepended bytes
	padLen, index, err := analysis.FindAlignment(oracle, blockSize, byte('A'))
	if err != nil {
		return nil, fmt.Errorf("alignment detection failure: %w", err)
	}

	// DEBUG
	fmt.Printf("Pad length: %d\n", padLen)
	fmt.Printf("Index: %d\n", index)

	// Align oracle
	alignedOracle := analysis.WrapOracle(oracle, padLen, index, blockSize)

	// Decrypt using BAAT ECB decryption using aligned oracle
	data, err := analysis.ByteAtATimeECB(alignedOracle, blockSize, len(appendBytes))
	if err != nil {
		return nil, fmt.Errorf("byte at a time decryption failed: %w", err)
	}

	// return ct, nil
	return data, nil
}

func runChallenge14() error {
	// Run challenge
	decData, err := Challenge14()
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// What we want
	want := `Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by`

	// DEBUG
	fmt.Printf("\nDecrypted: %s\n", decData)
	fmt.Printf("Expected:  %s\n\n", want)

	// See if we got what we wanted
	if !strings.Contains(string(decData), want) {
		return fmt.Errorf("result doesn't match expected value")
	}

	// Alert
	fmt.Println("[i] Challenge passed")

	return nil
}
