package crypto

import (
	"fmt"
	"testing"
)

func TestAes(t *testing.T) {
	aes := &Aes{cipher: []byte("abcdef0123456789")}

	data, _ := aes.Encrypt("abcdef")
	str := string(data)
	fmt.Println("encrypt:", data)
	fmt.Println("len:", len(str))
}
