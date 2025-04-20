package main

import (
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/set1"
)

func main() {
	messageEnc := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	key, message, score, err := set1.Challenge03(messageEnc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Message: %s\n", message)
	fmt.Printf("Key: %s\n", key)
	fmt.Printf("Score: %f\n", score)
}
