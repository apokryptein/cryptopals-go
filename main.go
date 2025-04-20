package main

import (
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/set1"
)

func main() {
	filePath := "./testdata/set1-challenge04_data.txt"

	encData, decData, key, err := set1.Challenge04(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}

	fmt.Printf("Encrypted: %s\n", encData)
	fmt.Printf("Decrypted: %s\n", decData)
	fmt.Printf("Key: %s\n", key)
}
