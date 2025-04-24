package main

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"

	"github.com/apokryptein/cryptopals-go/internal/cryptanalysis"
)

func main() {
	pt := "This is a test string to see if this things works. Or not..."
	s, _ := cryptanalysis.EncryptionOracle([]byte(pt))
	fmt.Println(hex.EncodeToString(s))

	result := cryptanalysis.DetectAES_ECB(s, aes.BlockSize)
	fmt.Println(result)

	if result {
		fmt.Println("Is ECB")
	} else {
		fmt.Println("Is CBC")
	}
}
