package set1_test

import (
	"strings"
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set1"
)

func TestChallenge06(t *testing.T) {
	wantKey := "Terminator X: Bring the noise"
	wantPrefix := "I'm back and I'm ringin' the bell"

	key, plaintext, err := set1.Challenge06("../../testdata/set1-challenge06_data.txt")
	if err != nil {
		t.Errorf("unexpected error: %v\n", err)
	}

	if key != wantKey || !strings.HasPrefix(plaintext, wantPrefix) {
		t.Errorf("wanted key: %s\ngot key: %s\n", wantKey, key)
	}
}
