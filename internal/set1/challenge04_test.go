package set1_test

import (
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set1"
)

func TestChallenge04(t *testing.T) {
	wantEncrypted := "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
	wantDecrypted := "Now that the party is jumping"
	wantKey := "5"

	filePath := "../../testdata/set1-challenge04_data.txt"

	gotEncrypted, gotDecrypted, gotKey, err := set1.Challenge04(filePath)
	if err != nil {
		t.Errorf("unexpected error: %v\n", err)
	}

	if gotEncrypted != wantEncrypted && gotDecrypted != wantDecrypted && gotKey != wantKey {
		t.Errorf("wanted: %s, %s, %s\ngot: %s, %s, %s\n", wantEncrypted, wantDecrypted, wantKey, gotEncrypted, gotDecrypted, gotKey)
	}
}
