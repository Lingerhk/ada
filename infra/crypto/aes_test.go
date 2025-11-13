package crypto

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestAes(t *testing.T) {
	aes := &Aes{cipher: []byte("3a43d7a31b3ca37d")}

	data, _ := aes.Encrypt("abcdef")
	str := string(data)
	fmt.Println("encrypt:", data)
	fmt.Println("len:", len(str))

	// Decrypt the data
	encByte, err := base64.StdEncoding.DecodeString("DykZr1+oybvC+E+Kmtz4lA==")
	if err != nil {
		t.Fatal(err)
	}

	decryptedData, _ := aes.Decrypt(encByte)
	fmt.Printf("decrypt: %s\n", decryptedData)
	fmt.Println("len:", len(decryptedData))
}
