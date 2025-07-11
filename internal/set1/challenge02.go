package set1

import (
	"encoding/hex"
	"fmt"

	"github.com/apokryptein/cryptopals-go/encoding"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         1,
		Number:      2,
		Name:        "Fixed XOR",
		Description: "XOR two equal-length buffers",
		Implemented: true,
		Run:         runChallenge02,
	})
}

func Challenge02(buf1 string, buf2 string) ([]byte, error) {
	buf1Bytes, err := hex.DecodeString(buf1)
	if err != nil {
		return nil, fmt.Errorf("error decoding hex: %w", err)
	}

	buf2Bytes, err := hex.DecodeString(buf2)
	if err != nil {
		return nil, fmt.Errorf("error decoding hex: %w", err)
	}

	return encoding.FixedXOR(buf1Bytes, buf2Bytes)
}

func runChallenge02() error {
	buf1 := "1c0111001f010100061a024b53535009181c"
	buf2 := "686974207468652062756c6c277320657965"
	wantResult := "746865206b696420646f6e277420706c6179"

	result, err := Challenge02(buf1, buf2)
	if err != nil {
		return fmt.Errorf("XOR failed: %w", err)
	}

	// Convert result to hex
	hexRes := hex.EncodeToString(result)

	// DEBUG
	fmt.Printf("Output:     %s\n", hexRes)
	fmt.Printf("Expected:   %s\n", wantResult)

	// Check the result
	if hexRes != wantResult {
		return fmt.Errorf("result doesn't match expected value")
	}

	// Alert
	fmt.Println("[i] Challenge passed")
	return nil
}
