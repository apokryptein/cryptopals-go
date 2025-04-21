package set1_test

import (
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set1"
)

func TestChallenge08(t *testing.T) {
	wantResult := "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
	gotResult, err := set1.Challenge08("../../testdata/set1-challenge08_data.txt")
	if err != nil {
		t.Errorf("unexpected error: %v\n", err)
		return
	}

	if gotResult != wantResult {
		t.Errorf("wanted: %s\ngot: %s\n", wantResult, gotResult)
	}
}
