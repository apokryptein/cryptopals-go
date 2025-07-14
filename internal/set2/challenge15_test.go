package set2_test

import (
	"fmt"
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func TestChallenge15(t *testing.T) {
	// Test data
	testData := "ICE ICE BABY\x04\x04\x04\x04"
	want := "ICE ICE BABY"

	// Run challenge
	stripped, err := set2.Challenge15([]byte(testData))
	if err != nil {
		t.Errorf("[ERR] padding validation failed: %v", err)
	}

	// DEBUG
	fmt.Printf("Stripped plaintext: %s\n", string(stripped))
	fmt.Printf("Expected plaintext: %s\n", want)

	// Validate result
	if want != string(stripped) {
		t.Errorf("[ERR] result doesn't match expected value")
	}
}
