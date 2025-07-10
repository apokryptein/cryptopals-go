package set2

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/apokryptein/cryptopals-go/crypto"
	"github.com/apokryptein/cryptopals-go/encoding"
)

func Challenge13() (*encoding.Profile, error) {
	// UID generator
	uidGen := &encoding.UIDGen{ID: 10}

	// Generate new profile from email
	profile, err := encoding.NewProfile("foo@bar.com", uidGen)
	if err != nil {
		return nil, fmt.Errorf("failed to create new profile: %w", err)
	}

	// Marshal
	jsonPro, err := json.MarshalIndent(profile, "", " ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal profile: %w", err)
	}

	// DEBUG
	fmt.Printf("=== New Original Profile ===\n%s\n", string(jsonPro))

	// Convert to encoded cookie format
	proCookie := profile.ProfileToCookie()
	fmt.Printf("Original Profile Cookie => %s\n\n", proCookie)

	// Generate random 16-byte key
	key := make([]byte, aes.BlockSize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("key gen: %w", err)
	}

	// Set up admin cookie to check encrypted block differences
	adminCookie := "email=foo@bar.com&uid=10&role=admin"

	// Encrypt valid profile cookie
	proEnc, err := crypto.EncryptAESECB(key, []byte(proCookie))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	// Encrypt malicious profile cookie
	adminEnc, err := crypto.EncryptAESECB(key, []byte(adminCookie))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	// Construct forged cookie
	forgedCookie := proEnc[:16]
	forgedCookie = append(forgedCookie, adminEnc[16:]...)

	// Decrypte forged cookie
	forgedDec, err := crypto.DecryptAESECB(key, forgedCookie)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Clean up string
	cleanForged := strings.TrimSpace(string(forgedDec))

	// Create new profile from cookie
	forgedProfile := &encoding.Profile{}
	forgedProfile.ProfileFromCookie(cleanForged)

	jsonForged, err := json.MarshalIndent(forgedProfile, "", " ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal profile: %w", err)
	}

	// DEBUG
	fmt.Printf("=== Forged Profile ===\n%s\n\n", string(jsonForged))

	return forgedProfile, nil
}
