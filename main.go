package main

import (
	"crypto/aes"
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/cryptanalysis"
	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func main() {
	// Build and encrypt data for challenge
	encData, err := set2.Challenge12()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] %v", err)
		os.Exit(1)
	}

	// DEBUG
	if ok := cryptanalysis.DetectAES_ECB(encData, aes.BlockSize); ok {
		fmt.Println("ECB")
	} else {
		fmt.Println("Something's wrong")
	}
}
