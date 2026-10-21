// Package sanitize validates and escapes user-controlled values that end up in
// operating-system commands executed by the sensor (threat blocking policies).
//
// The backend and the sensor both call these helpers so that a value is checked
// before it is published to the sensor and again before it is executed.
package sanitize

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Maximum length accepted for an account identifier (AD sAMAccountName is
// limited to 256 characters; user accounts are limited to 20).
const maxAccountNameLen = 256

// accountNamePattern allows letters (any script), digits and the few
// punctuation characters that are legal in a sAMAccountName. Everything that
// has a meaning for PowerShell or the AD cmdlets (quotes, $(), ;, |, &, `,
// braces, whitespace, comma, backslash, ...) is rejected.
var accountNamePattern = regexp.MustCompile(`^[\p{L}\p{N}._$-]+$`)

var (
	ErrEmptyAccountName   = errors.New("account name is empty")
	ErrAccountNameTooLong = fmt.Errorf("account name exceeds %d characters", maxAccountNameLen)
	ErrInvalidAccountName = errors.New("account name contains characters that are not allowed")
	ErrInvalidIP          = errors.New("value is not a valid IP address or CIDR")
)

// ValidateAccountName checks that name can be passed to Set-ADUser/Get-ADUser
// as an -Identity argument without any risk of command injection.
func ValidateAccountName(name string) error {
	if name == "" {
		return ErrEmptyAccountName
	}
	if len(name) > maxAccountNameLen {
		return ErrAccountNameTooLong
	}
	if !accountNamePattern.MatchString(name) {
		return ErrInvalidAccountName
	}
	return nil
}

// ValidateIPOrCIDR checks that value is a single IPv4/IPv6 address or a CIDR
// prefix, which is what New-NetFirewallRule -RemoteAddress accepts. It returns
// the canonical textual form.
func ValidateIPOrCIDR(value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", ErrInvalidIP
	}
	if addr, err := netip.ParseAddr(v); err == nil {
		if addr.Zone() != "" {
			return "", ErrInvalidIP
		}
		return addr.String(), nil
	}
	if prefix, err := netip.ParsePrefix(v); err == nil {
		if prefix.Addr().Zone() != "" {
			return "", ErrInvalidIP
		}
		return prefix.Masked().String(), nil
	}
	return "", ErrInvalidIP
}

// ValidateAccountNames validates every entry of list and reports the first
// invalid one.
func ValidateAccountNames(list []string) error {
	for _, name := range list {
		if err := ValidateAccountName(name); err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
	}
	return nil
}

// ValidateIPList validates every entry of list and reports the first invalid
// one.
func ValidateIPList(list []string) error {
	for _, ip := range list {
		if _, err := ValidateIPOrCIDR(ip); err != nil {
			return fmt.Errorf("%q: %w", ip, err)
		}
	}
	return nil
}

// PowerShellQuote returns value as a PowerShell single-quoted string literal.
// Inside single quotes PowerShell performs no interpolation; the only character
// that needs escaping is the single quote itself, which is doubled.
func PowerShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
