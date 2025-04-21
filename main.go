package main

import (
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

func main() {
	key := "YELLOW SUBMARINE"

	newKey, err := crypto.PaddingPKCS7([]byte(key), 25)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("New Key: |%s|\n", string(newKey))
	fmt.Printf("%x\n", newKey)
}
