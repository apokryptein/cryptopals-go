package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
)

func main() {
	key := "YELLOW SUBMARINE"

	data, err := os.ReadFile("./testdata/set2-challenge10_data.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening file: %v\n", err)
		os.Exit(1)
	}

	cleanData := strings.ReplaceAll(string(data), "\n", "")
	decData, err := base64.StdEncoding.DecodeString(cleanData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding hex: %v\n", err)
		os.Exit(1)
	}

	iv := bytes.Repeat([]byte("0"), 16)

	pt, err := crypto.DecryptAES_CBC([]byte(key), iv, []byte(decData))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decrypting data: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(pt))
}
