package set1_test

import (
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set1"
)

func TestChallenge05(t *testing.T) {
	data := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	wantResult := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	encData, err := set1.Challenge05(data, key)
	if err != nil {
		t.Errorf("unexpected error: %v\n", err)
	}

	if encData != wantResult {
		t.Errorf("wanted; %s\ngot: %s\n", wantResult, encData)
	}
}
