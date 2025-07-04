package set2

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/apokryptein/cryptopals-go/internal/encoding"
)

func Challenge13() error {
	// UID generator
	uidGen := &encoding.UIDGen{ID: 10}

	// Generate new profile from email
	profile, err := encoding.NewProfile("foo@bar.com", uidGen)
	if err != nil {
		return fmt.Errorf("failed to create new profile: %w", err)
	}

	// Marshal
	jsonPro, err := json.MarshalIndent(profile, "", " ")
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	// DEBUG
	fmt.Printf("New profile:\n%s\n", string(jsonPro))

	// Conver to encoded cookie format
	proCookie := profile.ProfileToCookie()
	fmt.Printf("Profile cookie: %s\n", proCookie)

	// Generate random 16-byte key
	key := make([]byte, aes.BlockSize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("key gen: %w", err)
	}

	// TODO:
	// 1. encrypt profiles only differing by group (user vs. admin)
	// 2. Identify the block holding the user group data
	// 3. Replace the data in encrypted profile
	// 4. Decrypt with key and compare

	return nil
}
