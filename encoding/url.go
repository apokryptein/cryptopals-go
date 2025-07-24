package encoding

import "strings"

// QuoteString replaces all characters in a string given a map of characters to replace
// with their replacement
func QuoteString(s string, chars map[string]string) string {
	// Iterate over provided char map and replace
	for char, replacement := range chars {
		s = strings.ReplaceAll(s, char, replacement)
	}

	return s
}
