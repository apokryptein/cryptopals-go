// Package runner implements logic for interacting with Cryptopals challenges
// from the CLI
package runner

import (
	"fmt"
	"sync"
)

// Challenge represents a single challenge
type Challenge struct {
	Set         int
	Number      int
	Name        string
	Description string
	Implemented bool
	Run         func() error
}

var (
	challenges = make(map[string]*Challenge)
	mu         sync.RWMutex
)

// Register registers a challenge in the challenges map
func Register(c *Challenge) {
	mu.Lock()
	defer mu.Unlock()

	// Create key for map
	key := fmt.Sprintf("%d-%d", c.Set, c.Number)

	// Store challenge in challenges map
	challenges[key] = c
}

// GetAll retrieves all registered challenges and returns them in a slice
func GetAll() []*Challenge {
	mu.RLock()
	defer mu.RUnlock()

	// Iterate over challneges, store in all, then return slice
	var all []*Challenge
	for _, c := range challenges {
		all = append(all, c)
	}

	return all
}

// Run pulls and runs a challenge based on provided set and challenge numbers
func Run(set, challenge int) error {
	mu.RLock()
	defer mu.RUnlock()

	// Build key
	key := fmt.Sprintf("%d-%d", set, challenge)

	// Get challenge and ensure it exists
	c, exists := challenges[key]
	if !exists {
		return fmt.Errorf("challenge %d-%d not found", set, challenge)
	}

	// Check for implementation status
	if !c.Implemented {
		return fmt.Errorf("challenge %d-%d not yet implemented", set, challenge)
	}

	fmt.Printf("\n=== Set %d, Challenge %d: %s ===\n", c.Set, c.Number, c.Name)
	fmt.Println()

	// Run the challenge
	return c.Run()
}
