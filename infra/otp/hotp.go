package otp

// HOTP implements HMAC-based OTP counter
type HOTP struct {
	OTP
}

func NewHOTP(secret string, digits int, hasher *Hasher) *HOTP {
	otp := NewOTP(secret, digits, hasher)
	return &HOTP{OTP: otp}

}

// NewDefaultHOTP creates a default OTP object
func NewDefaultHOTP(secret string) *HOTP {
	return NewHOTP(secret, 6, nil)
}

// At generates OTP value based on given integer
func (h *HOTP) At(count int) string {
	return h.generateOTP(count)
}

// Verify validates OTP
/**
Parameters:
	otp:    OTP value to check
    count:  HMAC counter for OTP verification
Returns:
	bool    Whether verification succeeded, returns true on success
*/
func (h *HOTP) Verify(otp string, count int) bool {
	return otp == h.At(count)
}

// ProvisioningUri gets URI for OTP verification, can be embedded in QR code
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
/**
Parameters:
	accountName:     Account name
    issuerName:      OTP issuer name, this is the organization title for OTP
    initialCount:    Initial HMAC counter value
Returns:
	URI for verification
*/
func (h *HOTP) ProvisioningUri(accountName, issuerName string, initialCount int) string {
	return BuildUri(
		OtpTypeHotp,
		h.secret,
		accountName,
		issuerName,
		h.hasher.HashName,
		initialCount,
		h.digits,
		0)
}
