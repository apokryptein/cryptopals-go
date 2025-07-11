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
		// Run:         runChallenge02,
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
