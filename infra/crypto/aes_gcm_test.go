package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestAesGCM_EncryptDecrypt(t *testing.T) {
	// Test with AES-256 (32 bytes)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	gcm, err := NewAesGCM(key)
	if err != nil {
		t.Fatalf("Failed to create AesGCM: %v", err)
	}

	testCases := []string{
		"password123",
		"P@ssw0rd!Complex",
		"域管理员密码",
		"a",
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
	}

	for _, plaintext := range testCases {
		t.Run(plaintext, func(t *testing.T) {
			// Encrypt
			ciphertext, err := gcm.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify ciphertext is not empty
			if len(ciphertext) == 0 {
				t.Fatal("Ciphertext is empty")
			}

			// Verify ciphertext is different from plaintext
			if string(ciphertext) == plaintext {
				t.Fatal("Ciphertext should be different from plaintext")
			}

			// Decrypt
			decrypted, err := gcm.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify decrypted text matches original
			if string(decrypted) != plaintext {
				t.Fatalf("Decrypted text doesn't match. Got: %s, Want: %s", string(decrypted), plaintext)
			}
		})
	}
}

func TestAesGCM_RandomNonce(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	gcm, err := NewAesGCM(key)
	if err != nil {
		t.Fatalf("Failed to create AesGCM: %v", err)
	}

	plaintext := "test password"

	// Encrypt the same plaintext multiple times
	ciphertext1, err := gcm.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	ciphertext2, err := gcm.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Verify that different encryptions produce different ciphertexts
	// (due to random nonce)
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Fatal("Same plaintext should produce different ciphertexts due to random nonce")
	}

	// But both should decrypt to the same plaintext
	decrypted1, err := gcm.Decrypt(ciphertext1)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	decrypted2, err := gcm.Decrypt(ciphertext2)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}

	if string(decrypted1) != plaintext || string(decrypted2) != plaintext {
		t.Fatal("Decrypted text doesn't match original")
	}
}

func TestAesGCM_InvalidKey(t *testing.T) {
	invalidKeys := [][]byte{
		make([]byte, 8),  // Too short
		make([]byte, 15), // Invalid size
		make([]byte, 17), // Invalid size
		make([]byte, 64), // Too long
	}

	for _, key := range invalidKeys {
		_, err := NewAesGCM(key)
		if err != ErrInvalidKeySize {
			t.Errorf("Expected ErrInvalidKeySize for key length %d, got: %v", len(key), err)
		}
	}
}

func TestAesGCM_ValidKeySizes(t *testing.T) {
	validSizes := []int{16, 24, 32} // AES-128, AES-192, AES-256

	for _, size := range validSizes {
		key := make([]byte, size)
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("Failed to generate random key: %v", err)
		}

		gcm, err := NewAesGCM(key)
		if err != nil {
			t.Errorf("Failed to create AesGCM with valid key size %d: %v", size, err)
			continue
		}

		// Test encryption/decryption works
		plaintext := "test"
		ciphertext, err := gcm.Encrypt(plaintext)
		if err != nil {
			t.Errorf("Encryption failed with key size %d: %v", size, err)
			continue
		}

		decrypted, err := gcm.Decrypt(ciphertext)
		if err != nil {
			t.Errorf("Decryption failed with key size %d: %v", size, err)
			continue
		}

		if string(decrypted) != plaintext {
			t.Errorf("Decryption result mismatch with key size %d", size)
		}
	}
}

func TestAesGCM_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	gcm, err := NewAesGCM(key)
	if err != nil {
		t.Fatalf("Failed to create AesGCM: %v", err)
	}

	_, err = gcm.Encrypt("")
	if err != ErrEmptyContent {
		t.Errorf("Expected ErrEmptyContent for empty plaintext, got: %v", err)
	}
}

func TestAesGCM_InvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	gcm, err := NewAesGCM(key)
	if err != nil {
		t.Fatalf("Failed to create AesGCM: %v", err)
	}

	testCases := []struct {
		name       string
		ciphertext []byte
	}{
		{"too short", []byte{1, 2, 3}},
		{"empty", []byte{}},
		{"corrupted", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := gcm.Decrypt(tc.ciphertext)
			if err == nil {
				t.Error("Expected decryption to fail for invalid ciphertext")
			}
		})
	}
}

func TestAesGCM_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	gcm, err := NewAesGCM(key)
	if err != nil {
		t.Fatalf("Failed to create AesGCM: %v", err)
	}

	plaintext := "sensitive password"
	ciphertext, err := gcm.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Tamper with the ciphertext
	if len(ciphertext) > 15 {
		ciphertext[15] ^= 0xFF // Flip bits in the middle
	}

	// Decryption should fail due to authentication failure
	_, err = gcm.Decrypt(ciphertext)
	if err == nil {
		t.Error("Expected decryption to fail for tampered ciphertext")
	}
}

func TestAesGCM_Base64Encoding(t *testing.T) {
	// Test with base64 encoding (like it's used in the actual application)
	key := []byte("12345678901234567890123456789012") // 32 bytes

	gcm, err := NewAesGCM(key)
	if err != nil {
		t.Fatalf("Failed to create AesGCM: %v", err)
	}

	plaintext := "Administrator@domain.com:P@ssw0rd123"

	// Encrypt
	ciphertext, err := gcm.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Encode to base64 (like in PasswordEncrypt)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	// Decode from base64 (like in PasswordDecode)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Base64 decode failed: %v", err)
	}

	// Decrypt
	decrypted, err := gcm.Decrypt(decoded)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Fatalf("Decrypted text doesn't match. Got: %s, Want: %s", string(decrypted), plaintext)
	}
}

func TestAesGCM_StringMethods(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	gcm, err := NewAesGCM(key)
	if err != nil {
		t.Fatalf("Failed to create AesGCM: %v", err)
	}

	plaintext := "test password 123"

	// Test EncryptString
	ciphertext, err := gcm.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString failed: %v", err)
	}

	// Test DecryptString
	decrypted, err := gcm.DecryptString(ciphertext)
	if err != nil {
		t.Fatalf("DecryptString failed: %v", err)
	}

	if decrypted != plaintext {
		t.Fatalf("Decrypted text doesn't match. Got: %s, Want: %s", decrypted, plaintext)
	}
}
