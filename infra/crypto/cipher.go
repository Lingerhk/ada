package crypto

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

// MD5String generates MD5 hash and truncates it to specified length.
func MD5String(key string, length int) string {
	h := md5.New()
	h.Write([]byte(key))
	result := hex.EncodeToString(h.Sum(nil))
	if length > len(result) {
		length = len(result)
	}
	return result[:length]
}

// RandString generates a cryptographically secure random string of specified length.
// Uses crypto/rand for secure random number generation suitable for secrets,
// API keys, and other security-sensitive operations.
// This implementation uses rejection sampling via crypto/rand.Int to ensure
// uniform distribution without modulo bias.
func RandString(length int) string {
	s, err := RandStringE(length)
	if err != nil {
		return ""
	}
	return s
}

// RandStringE generates a cryptographically secure random string and returns an error on entropy failure.
func RandStringE(length int) (string, error) {
	const letterBytes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterBytesLen := big.NewInt(int64(len(letterBytes)))

	b := make([]byte, length)
	for i := range length {
		// crypto/rand.Int returns a uniform random value in [0, max)
		// This avoids modulo bias that occurs with simple modulo operation
		idx, err := rand.Int(rand.Reader, letterBytesLen)
		if err != nil {
			return "", err
		}
		b[i] = letterBytes[idx.Int64()]
	}

	return string(b), nil
}
