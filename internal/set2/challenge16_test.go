package set2_test

import (
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func TestChallenge16(t *testing.T) {
	// Run challenge
	ok, err := set2.Challenge16()
	if err != nil {
		t.Errorf("[ERR] ")
	}

	// Check for true
	if !ok {
		t.Errorf("[FAIL] test failed")
	}
}
