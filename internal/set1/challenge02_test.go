package set1_test

import (
	"encoding/hex"
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set1"
)

func TestChallenge02(t *testing.T) {
	buf1 := "1c0111001f010100061a024b53535009181c"
	buf2 := "686974207468652062756c6c277320657965"
	wantResult := "746865206b696420646f6e277420706c6179"

	gotResult, err := set1.Challenge02(buf1, buf2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hex.EncodeToString(gotResult) != wantResult {
		t.Errorf("=== mismatch ===\nwant: %q\ngot:%q\n", wantResult, gotResult)
	}
}
