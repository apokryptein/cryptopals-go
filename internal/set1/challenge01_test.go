package set1_test

import (
	"testing"

	"github.com/apokryptein/cryptopals-go/encoding"
)

func TestChallenge01(t *testing.T) {
	hexInput := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	wantResult := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	gotResult, err := encoding.HexToBase64(hexInput)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotResult != wantResult {
		t.Errorf("=== mismatch ===\nwant: %q\ngot:%q\n", wantResult, gotResult)
	}
}
