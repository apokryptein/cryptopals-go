package set2_test

import (
	"strings"
	"testing"

	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func TestChallenge14(t *testing.T) {
	// Run challenge
	decData, err := set2.Challenge14()
	if err != nil {
		t.Errorf("[ERR] %v\n", err)
	}

	// What we want
	want := `Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by`

	// See if we got what we wanted
	if !strings.Contains(string(decData), want) {
		t.Errorf("wanted:\n%s\n\ngot:\n%s\n", want, string(decData))
	}
}
