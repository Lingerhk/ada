package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"fmt"
	"hash"
	"math"
	"strings"
)

var ErrInvalidOTPInput = errors.New("otp input must be positive integer")

type Hasher struct {
	HashName string
	Digest   func() hash.Hash
}

type OTP struct {
	secret string  // Base32 encoded Secret
	digits int     // Integer in OTP, some applications use 6 digits or more
	hasher *Hasher // Digest used in HMAC (default is sha1)
}

// NewOTP creates a new OTP object
func NewOTP(secret string, digits int, hasher *Hasher) OTP {
	if hasher == nil {
		hasher = &Hasher{
			HashName: "sha1",
			Digest:   sha1.New,
		}
	}
	return OTP{
		secret: secret,
		digits: digits,
		hasher: hasher,
	}
}

// generateOTP generates OTP
/**
Parameters:
	input:  HMAC counter value used as OTP input, typically a counter or Unix timestamp
*/
func (o *OTP) generateOTP(input int) string {
	code, err := o.GenerateOTP(input)
	if err != nil {
		return ""
	}
	return code
}

func (o *OTP) GenerateOTP(input int) (string, error) {
	if input < 0 {
		return "", ErrInvalidOTPInput
	}
	secret, err := o.byteSecret()
	if err != nil {
		return "", err
	}
	hasher := hmac.New(o.hasher.Digest, secret)
	hasher.Write(Itob(input))
	hmacHash := hasher.Sum(nil)

	offset := int(hmacHash[len(hmacHash)-1] & 0xf)
	code := ((int(hmacHash[offset]) & 0x7f) << 24) |
		((int(hmacHash[offset+1] & 0xff)) << 16) |
		((int(hmacHash[offset+2] & 0xff)) << 8) |
		(int(hmacHash[offset+3]) & 0xff)

	code = code % int(math.Pow10(o.digits))
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", o.digits), code), nil
}

func (o *OTP) byteSecret() ([]byte, error) {
	missingPadding := len(o.secret) % 8
	if missingPadding != 0 {
		o.secret = o.secret + strings.Repeat("=", 8-missingPadding)
	}
	//ciphertext := strings.Replace(o.secret, " ", "", -1)
	bytes, err := base32.StdEncoding.DecodeString(o.secret)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
