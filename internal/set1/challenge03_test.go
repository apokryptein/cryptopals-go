package set1_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set1"
)

func TestChallenge03(t *testing.T) {
	messageEnc := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	wantMessage := "Cooking MC's like a pound of bacon"
	wantKey := "X"

	gotKey, gotMessage, _, err := set1.Challenge03(messageEnc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}

	if gotMessage != wantMessage && gotKey != wantKey {
		t.Errorf("wanted: %s, %s\ngot: %s, %s\n", wantKey, wantMessage, gotKey, gotMessage)
	}
}
