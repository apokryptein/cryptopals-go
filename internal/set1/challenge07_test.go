package set1_test

import (
	"strings"
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set1"
)

func TestChallenge07(t *testing.T) {
	wantResult := "I'm back and I'm ringin' the bell"

	pt, err := set1.Challenge07("../../testdata/set1-challenge07_data.txt")
	if err != nil {
		t.Errorf("unexpected error: %v\n", err)
	}

	if !strings.HasPrefix(pt, wantResult) {
		t.Errorf("want:\n%s\n\ngot:\n%s\n", wantResult, pt)
	}
}
