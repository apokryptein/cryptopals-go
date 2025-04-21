package main

import (
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/set1"
)

func main() {
	key, plaintext, err := set1.Challenge06("./testdata/set1-challenge06_data.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("KEY: %s\n", key)
	fmt.Println(plaintext)
}
