package crypto

import (
	"bytes"
	"fmt"
)

// PaddingPKCS7 implements the PKCS7 padding standard
func PaddingPKCS7(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize >= 256 {
		return nil, fmt.Errorf("invalid bock size")
	}

	padLen := blockSize - (len(data) % blockSize)

	if padLen == 0 {
		padLen = blockSize
	}

	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)

	return append(data, pad...), nil
}

// ValidatePadding validates the PKCS7 padding of a given plaintext
// and if valid returns the plaintext stripped of padding
func ValidatePadding(pt []byte, blockSize int) ([]byte, error) {
	// Check that pt aligns
	if padLen := len(pt) % blockSize; padLen != 0 {
		return nil, fmt.Errorf("padding invalid")
	}

	// Get last value
	lastInd := len(pt) - 1
	pad := pt[lastInd]

	// Validate pad length
	if pad == 0 || pad > byte(blockSize) {
		return nil, fmt.Errorf("padding invalid due to length")
	}

	// Build ideal pad
	fullPad := bytes.Repeat([]byte{pad}, int(pad))

	// Ensure pt has correct pad
	if !bytes.HasSuffix(pt, fullPad) {
		return nil, fmt.Errorf("padding invalid")
	}

	// Retcurn slice of pt up to pad
	return pt[:lastInd-int(pad)+1], nil
}
