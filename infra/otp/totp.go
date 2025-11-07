package otp

import (
	"time"
)

// TOTP implements time-based OTP counter
type TOTP struct {
	OTP
	interval int
}

func NewTOTP(secret string, digits, interval int, hasher *Hasher) *TOTP {
	otp := NewOTP(secret, digits, hasher)
	return &TOTP{OTP: otp, interval: interval}
}

// NewDefaultTOTP creates a default OTP object
func NewDefaultTOTP(secret string) *TOTP {
	return NewTOTP(secret, 6, 30, nil)
}

// At generates OTP value based on given timestamp
func (t *TOTP) At(timestamp int) string {
	return t.generateOTP(t.timecode(timestamp))
}

// Now generates OTP value for current time
func (t *TOTP) Now() string {
	return t.At(CurrentTimestamp())
}

// NowWithExpiration generates OTP value for current time and returns expiration time
func (t *TOTP) NowWithExpiration() (string, int64) {
	interval64 := int64(t.interval)
	timeCodeInt64 := time.Now().Unix() / interval64
	expirationTime := (timeCodeInt64 + 1) * interval64
	return t.generateOTP(int(timeCodeInt64)), expirationTime
}

// Verify validates OTP
/**
Parameters:
	otp:         OTP value to check
    timestamp:   Timestamp for OTP verification
Returns:
	bool    Whether verification succeeded, returns true on success
*/
func (t *TOTP) Verify(otp string, timestamp int) bool {
	return otp == t.At(timestamp)
}

// ProvisioningUri gets URI for OTP verification, can be embedded in QR code
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
/**
Parameters:
	accountName:     Account name
    issuerName:      OTP issuer name, this is the organization title for OTP
Returns:
	URI for verification
*/
func (t *TOTP) ProvisioningUri(accountName, issuerName string) string {
	return BuildUri(
		OtpTypeTotp,
		t.secret,
		accountName,
		issuerName,
		t.hasher.HashName,
		0,
		t.digits,
		t.interval)
}

func (t *TOTP) timecode(timestamp int) int {
	return int(timestamp / t.interval)
}
