package otp

import (
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

const (
	OtpTypeTotp = "totp"
	OtpTypeHotp = "hotp"
)

// BuildUri generates URI for OTP verification (applicable to both TOTP and HOTP)
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
/**
Parameters:
    otpType:         OTP type, must be totp/hotp
    secret:          hotp/totp secret for generating URI
    accountName:     Account name
    issuerName:      OTP issuer name, this is the organization title for OTP
    algorithm:       Algorithm name
    initialCount:    Counter start value, only used for hotp
    digits:          Length of generated OTP code
    period:          Expiration time of OTP code (seconds)
Returns:
	URI for OTP verification
*/
func BuildUri(otpType, secret, accountName, issuerName, algorithm string, initialCount, digits, period int) string {
	if otpType != OtpTypeHotp && otpType != OtpTypeTotp {
		panic("otp type error, got " + otpType)
	}

	urlParams := make([]string, 0)
	urlParams = append(urlParams, "secret="+secret)
	if otpType == OtpTypeHotp {
		urlParams = append(urlParams, fmt.Sprintf("counter=%d", initialCount))
	}
	label := url.QueryEscape(accountName)
	if issuerName != "" {
		issuerNameEscape := url.QueryEscape(issuerName)
		label = issuerNameEscape + ":" + label
		urlParams = append(urlParams, "issuer="+issuerNameEscape)
	}
	if algorithm != "" && algorithm != "sha1" {
		urlParams = append(urlParams, "algorithm="+strings.ToUpper(algorithm))
	}
	if digits != 0 && digits != 6 {
		urlParams = append(urlParams, fmt.Sprintf("digits=%d", digits))
	}
	if period != 0 && period != 30 {
		urlParams = append(urlParams, fmt.Sprintf("period=%d", period))
	}
	return fmt.Sprintf("otpauth://%s/%s?%s", otpType, label, strings.Join(urlParams, "&"))
}

// CurrentTimestamp gets current timestamp
func CurrentTimestamp() int {
	return int(time.Now().Unix())
}

// Itob converts integer to byte array
func Itob(integer int) []byte {
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(integer & 0xff)
		integer = integer >> 8
	}
	return byteArr
}

// RandomSecret generates random secret based on length
func RandomSecret(length int) string {
	rand.Seed(time.Now().UnixNano())
	//letterRunes := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*_+=")
	letterRunes := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

	bytes := make([]rune, length)

	for i := range bytes {
		bytes[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	return string(bytes)
}
