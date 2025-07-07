package main

import (
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func main() {
	_, err := set2.Challenge13()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Challenge 13 failure: %v\n", err)
		os.Exit(1)
	}
}
