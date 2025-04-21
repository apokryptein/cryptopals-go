package set2_test

import (
	"strings"
	"testing"

	set2 "github.com/apokryptein/cryptopals-go/internal"
)

func TestChallenge09(t *testing.T) {
	wantSize := 25 // blockSize to match desired length
	wantString := "YELLOW SUBMARINE"

	got, err := set2.Challenge09(wantString, wantSize)
	if err != nil {
		t.Errorf("unexpected error: %v\n", err)
		return
	}

	if !strings.HasPrefix(string(got), wantString) || len(got) != wantSize {
		t.Errorf("wanted: %d\ngot: %d\n", wantSize, len(got))
	}
}
