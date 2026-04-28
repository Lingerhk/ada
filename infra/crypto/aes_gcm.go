package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

var (
	ErrEmptyContent      = errors.New("encrypt plain content empty")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrInvalidKeySize    = errors.New("invalid key size: must be 16, 24, or 32 bytes")
)

// AesGCM provides authenticated encryption using AES-GCM
// This is much more secure than ECB mode as it provides both confidentiality and authenticity
type AesGCM struct {
	key []byte
}

// NewAesGCM creates a new AES-GCM encryptor/decryptor
// keySize should be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes
func NewAesGCM(key []byte) (*AesGCM, error) {
	// Validate key size
	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, ErrInvalidKeySize
	}

	return &AesGCM{
		key: key,
	}, nil
}

// Encrypt encrypts plaintext using AES-GCM with a random nonce
// The nonce is prepended to the ciphertext, so the output format is: [nonce][ciphertext][tag]
func (a *AesGCM) Encrypt(plaintext string) ([]byte, error) {
	if plaintext == "" {
		return nil, ErrEmptyContent
	}

	// Create AES cipher block
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	// GCM standard nonce size is 12 bytes
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and authenticate
	// Format: nonce + ciphertext + authentication tag (tag is appended by Seal)
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext that was encrypted with Encrypt
// Expected format: [nonce][ciphertext][tag]
func (a *AesGCM) Decrypt(ciphertext []byte) ([]byte, error) {
	// Create AES cipher block
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DecryptString is a convenience method that decrypts to a string
func (a *AesGCM) DecryptString(ciphertext []byte) (string, error) {
	plaintext, err := a.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
