package set2_test

import (
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func TestChallenge13(t *testing.T) {
	// Run Challeng13 and get resululting profile
	forgedProfile, err := set2.Challenge13()
	if err != nil {
		t.Errorf("[ERR] failure running Challenge 13: %v", err)
	}

	// Profile cookie that we want
	want := "email=foo@bar.com&uid=10&role=admin"

	// Profile cookit that we got
	have := forgedProfile.ProfileToCookie()

	// Test
	if want != have {
		t.Errorf("[ERR] expected: %s\nresult: %s\n", want, have)
	}
}
