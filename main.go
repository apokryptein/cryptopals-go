package main

import (
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func main() {
	data, err := set2.Challenge14()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Challenge 14 failure: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(data))
}
