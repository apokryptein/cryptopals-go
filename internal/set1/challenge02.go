package set1

import "github.com/apokryptein/cryptopals-go/internal/encoding"

func Challenge02(buf1 string, buf2 string) (string, error) {
	return encoding.FixedXOR(buf1, buf2)
}
