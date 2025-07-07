package set2_test

import (
	"slices"
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func TestChallenge10(t *testing.T) {
	// What we want
	// NOTE: this includes padding bytes as we have not yet implemented padding
	// validation and removal
	want := []byte{121, 23, 93, 16, 82, 81, 83, 91, 16, 81, 94, 84, 16, 121, 23, 93}

	// Bytes we received
	got, err := set2.Challenge10("../../testdata/set2-challenge10_data.txt")
	if err != nil {
		t.Errorf("unexpected error: %v\n", err)
		return
	}

	// Check
	if !slices.Equal(want, got[:16]) {
		t.Errorf("\nwanted:\n%s\ngot:\n%s\n", want, string(got[:16]))
	}
}
