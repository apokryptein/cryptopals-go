package set2_test

import (
	"strings"
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func TestChallenge10(t *testing.T) {
	want := "y]RQS[Q^Ty] ringin' the bell"

	got, err := set2.Challenge10("../../testdata/set2-challenge10_data.txt")
	if err != nil {
		t.Errorf("unexpected error: %v\n", err)
		return
	}

	if !strings.HasPrefix(string(got), want) {
		t.Errorf("\nwanted:\n%s\ngot:\n%s\n", want, string(got))
	}
}
