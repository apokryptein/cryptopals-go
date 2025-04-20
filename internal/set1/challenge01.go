package set1

import (
	"github.com/apokryptein/cryptopals-go/internal/encoding"
)

func Challenge01(hexString string) (string, error) {
	return encoding.HexToBase64(hexString)
}
