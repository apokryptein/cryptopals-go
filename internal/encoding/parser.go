package encoding

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// UIDGen is a user ID generator
type UIDGen struct {
	mu sync.Mutex
	ID int
}

// Increment is a receiver function for UIDGen and is reponsible for
// incrementing the user ID value for new profile
func (u *UIDGen) Increment() int {
	u.mu.Lock()
	defer u.mu.Unlock()

	newID := u.ID
	u.ID++

	return newID
}

// Profile represents a user profile
type Profile struct {
	Email string `json:"email"`
	UID   int    `json:"uid"`
	Role  string `json:"role"`
}

// ProfileFromCookie creates a new profile from a given cookie of the following format:
// email=foo@bar.com&uid=10&role=user
func (p *Profile) ProfileFromCookie(encStr string) error {
	fields := strings.SplitSeq(encStr, "&")
	for field := range fields {
		entry := strings.Split(field, "=")
		switch strings.ToLower(entry[0]) {
		case "email":
			p.Email = entry[1]
		case "uid":
			uid, err := strconv.Atoi(entry[1])
			if err != nil {
				return fmt.Errorf("profile: failed to convert uid to int: %w", err)
			}
			p.UID = uid
		case "role":
			p.Role = entry[1]
		default:
			return fmt.Errorf("unrecognized field: %s", entry[0])
		}
	}

	return nil
}

// ProfileToCookie return the cookie string encoding for an existing profile
func (p Profile) ProfileToCookie() string {
	// Parse UID to int
	uid := strconv.Itoa(p.UID)
	return fmt.Sprintf("email=%s&uid=%s&role=%s", p.Email, uid, p.Role)
}

// NewProfile creates a new profile given an email address
func NewProfile(email string, uid *UIDGen) (*Profile, error) {
	// Ensure input is safe
	// Find index of & if it exists
	safeEmail := email
	if malInd := strings.Index(email, "&"); malInd > -1 {
		safeEmail = email[:malInd]
	}
	// Replace all characters
	replacer := strings.NewReplacer("=", "")
	safeEmail = replacer.Replace(safeEmail)

	return &Profile{
		Email: safeEmail,
		UID:   uid.Increment(),
		Role:  "user",
	}, nil
}
