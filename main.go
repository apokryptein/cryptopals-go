package main

import (
	"fmt"
	"os"

	"github.com/apokryptein/cryptopals-go/internal/cryptanalysis"
)

func main() {
	s1 := "this is a test"
	s2 := "wokka wokka!!!"

	result, err := cryptanalysis.HammingDistance([]byte(s1), []byte(s2))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error calculating hamming distance: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Hamming Distance: %d\n", result)
}
