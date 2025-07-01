package main

import (
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func main() {
	// Build and encrypt data for challenge
	data, err := set2.Challenge12()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
