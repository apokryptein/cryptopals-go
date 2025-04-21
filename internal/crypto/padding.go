package crypto

import (
	"bytes"
	"fmt"
)

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
