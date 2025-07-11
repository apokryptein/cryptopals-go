// Package set1 contains solution to Cryptopal's Set 1 problems
package set1

import (
	"github.com/apokryptein/cryptopals-go/encoding"
	"github.com/apokryptein/cryptopals-go/internal/runner"
)

func init() {
	runner.Register(&runner.Challenge{
		Set:         1,
		Number:      1,
		Name:        "Convert hex to base64",
		Description: "Convert a hex encoded string to base64",
		Implemented: true,
		// Run:         runChallenge01,
	})
}

func Challenge01(hexString string) (string, error) {
	return encoding.HexToBase64(hexString)
}
