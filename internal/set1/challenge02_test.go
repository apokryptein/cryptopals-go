package set1_test

import (
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/encoding"
)

func TestChallenge02(t *testing.T) {
	buf1 := "1c0111001f010100061a024b53535009181c"
	buf2 := "686974207468652062756c6c277320657965"
	wantResult := "746865206b696420646f6e277420706c6179"

	gotResult, err := encoding.FixedXOR(buf1, buf2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotResult != wantResult {
		t.Errorf("=== mismatch ===\nwant: %q\ngot:%q\n", wantResult, gotResult)
	}
}
