package util

import (
	"ada/backend/apiserver/common"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestPasswordEncryptDecrypt(t *testing.T) {
	testCases := []string{
		"simplePassword",
		"P@ssw0rd!Complex123",
		"administrator@domain.com",
		"域管理员密码",
		"DOMAIN\\Administrator",
		"a",
		"Very long password with special characters !@#$%^&*()_+-=[]{}|;:',.<>?/~`",
	}

	for _, password := range testCases {
		t.Run(password, func(t *testing.T) {
			// Encrypt the password
			encrypted, err := PasswordEncrypt(password)
			if err != nil {
				t.Fatalf("PasswordEncrypt failed: %v", err)
			}

			// Verify encrypted string is not empty
			if encrypted == "" {
				t.Fatal("Encrypted password is empty")
			}

			// Verify encrypted string is different from original
			if encrypted == password {
				t.Fatal("Encrypted password should be different from plaintext")
			}

			// Decrypt the password
			decrypted, err := PasswordDecode(encrypted)
			if err != nil {
				t.Fatalf("PasswordDecode failed: %v", err)
			}

			// Verify decrypted matches original
			if decrypted != password {
				t.Fatalf("Decrypted password doesn't match. Got: %s, Want: %s", decrypted, password)
			}
		})
	}
}

func TestPasswordEncrypt_Randomness(t *testing.T) {
	password := "testPassword123"

	// Encrypt the same password multiple times
	encrypted1, err := PasswordEncrypt(password)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := PasswordEncrypt(password)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Verify that encrypting the same password produces different results
	// This is expected due to the random nonce in AES-GCM
	if encrypted1 == encrypted2 {
		t.Fatal("Same password should produce different encrypted values due to random nonce")
	}

	// But both should decrypt to the same password
	decrypted1, err := PasswordDecode(encrypted1)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	decrypted2, err := PasswordDecode(encrypted2)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}

	if decrypted1 != password || decrypted2 != password {
		t.Fatal("Both decryptions should produce the original password")
	}
}

func TestPasswordDecode_InvalidInput(t *testing.T) {
	testCases := []struct {
		name      string
		encrypted string
	}{
		{"empty string", ""},
		{"invalid base64", "not-valid-base64!!!"},
		{"short ciphertext", "YWJj"},                 // "abc" in base64
		{"corrupted ciphertext", "SGVsbG8gV29ybGQh"}, // Valid base64 but invalid ciphertext
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PasswordDecode(tc.encrypted)
			if err == nil {
				t.Error("Expected PasswordDecode to fail for invalid input")
			}
		})
	}
}

func TestPasswordEncrypt_EmptyPassword(t *testing.T) {
	_, err := PasswordEncrypt("")
	if err == nil {
		t.Error("Expected PasswordEncrypt to fail for empty password")
	}
}

// Test that demonstrates the security improvement over ECB mode
func TestPasswordEncrypt_SecurityImprovement(t *testing.T) {
	// In ECB mode, identical plaintext blocks produce identical ciphertext blocks
	// In GCM mode, even identical passwords produce different ciphertexts
	passwords := []string{
		"DomainAdmin123",
		"DomainAdmin123", // Intentionally duplicate
		"DomainAdmin123", // Intentionally duplicate
	}

	encryptedPasswords := make([]string, len(passwords))
	for i, password := range passwords {
		encrypted, err := PasswordEncrypt(password)
		if err != nil {
			t.Fatalf("Encryption failed for password %d: %v", i, err)
		}
		encryptedPasswords[i] = encrypted
	}

	// All three encrypted values should be different (due to random nonce in GCM)
	if encryptedPasswords[0] == encryptedPasswords[1] ||
		encryptedPasswords[1] == encryptedPasswords[2] ||
		encryptedPasswords[0] == encryptedPasswords[2] {
		t.Error("GCM mode should produce different ciphertexts for identical plaintexts")
	}

	// But all should decrypt to the same password
	for i, encrypted := range encryptedPasswords {
		decrypted, err := PasswordDecode(encrypted)
		if err != nil {
			t.Fatalf("Decryption failed for password %d: %v", i, err)
		}
		if decrypted != "DomainAdmin123" {
			t.Errorf("Password %d decrypted incorrectly: got %s", i, decrypted)
		}
	}
}

func TestParseTokenRequiresHS256(t *testing.T) {
	claim := UserClaim{
		User:    "admin",
		Role:    common.RoleMgr,
		Priv:    common.PrivSuper,
		Expired: time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS384, claim)
	tokenStr, err := token.SignedString([]byte(common.JWT_SECRET))
	if err != nil {
		t.Fatalf("sign HS384 token: %v", err)
	}

	if _, err := ParseToken(tokenStr, common.JWT_SECRET); err == nil {
		t.Fatal("expected ParseToken to reject non-HS256 token")
	}
}

func TestParseTokenRejectsOversizedToken(t *testing.T) {
	tokenStr := make([]byte, maxJWTTokenLen+1)
	for i := range tokenStr {
		tokenStr[i] = 'a'
	}

	if _, err := ParseToken(string(tokenStr), common.JWT_SECRET); err == nil {
		t.Fatal("expected ParseToken to reject oversized token")
	}
}
