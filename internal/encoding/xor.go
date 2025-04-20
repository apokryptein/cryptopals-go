package encoding

import (
	"fmt"
)

// XORs two buffer of equal length
func FixedXOR(buf1, buf2 []byte) ([]byte, error) {
	if len(buf1) != len(buf2) {
		return nil, fmt.Errorf("buffer lengths differ")
	}

	var xorResult []byte
	for i := range buf1 {
		xorResult = append(xorResult, buf1[i]^buf2[i])
	}

	return xorResult, nil
}
