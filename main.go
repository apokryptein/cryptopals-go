package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/apokryptein/cryptopals-go/internal/crypto"
	"github.com/apokryptein/cryptopals-go/internal/encoding"
	"github.com/apokryptein/cryptopals-go/internal/set2"
)

func main() {
	// Instantiate new Profile
	p := &encoding.Profile{UID: 10}

	// Test cookie
	test := "email=foo@bar.com&uid=10&role=user"

	// Parse cookie to profile
	p.ProfileFromCookie(test)

	// Marshal and print
	jpData, _ := json.MarshalIndent(p, "", " ")
	fmt.Println(string(jpData))

	// New Profile UID incrementor
	uidGen := encoding.UIDGen{}

	// Create new profile, marshal, and print
	p1, _ := encoding.NewProfile("Test1@test.com", &uidGen)
	jsonData, _ := json.MarshalIndent(p1, "", " ")
	fmt.Println(string(jsonData))

	// Create new profile, marshal, and print
	p2, _ := encoding.NewProfile("Test2@test.com", &uidGen)
	jsonData2, _ := json.MarshalIndent(p2, "", " ")
	fmt.Println(string(jsonData2))

	// Malicious profile
	maliciousInput := "foo@bar.com&role=admin"
	p3, _ := encoding.NewProfile(maliciousInput, &uidGen)
	jsonData3, _ := json.MarshalIndent(p3, "", " ")
	fmt.Println(string(jsonData3))

	key := "testkeytestkey01"
	// Encryption Test
	encData, err := crypto.EncryptAESECB([]byte(key), jpData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to encrypt profile: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[i] Data encrypted: %d bytes\n", len(encData))

	// Decrytion test
	decData, err := crypto.DecryptAESECB([]byte(key), encData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to decrypt profile: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[i] Data decrypted: %d bytes\n", len(decData))

	if slices.Equal(decData, jpData) {
		fmt.Printf("[i] Data matches original\n")
	} else {
		fmt.Printf("[!] Data does not match\n")
	}

	fmt.Println(string(decData))

	fmt.Println("CHALLENGE 13")

	set2.Challenge13()
}
