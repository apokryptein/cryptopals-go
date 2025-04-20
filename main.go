package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

func main() {
	plaintext := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"

	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	result, err := crypto.RepeatingKeyXOR([]byte(plaintext), []byte(key))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error RepeatingKeyXOR: %v\n", err)
		os.Exit(1)
	}

	resultHex := hex.EncodeToString(result)

	fmt.Println(resultHex)

	if resultHex != want {
		fmt.Println("[!] No good")
		return
	}

	fmt.Println("[i] Looks good!")
}
