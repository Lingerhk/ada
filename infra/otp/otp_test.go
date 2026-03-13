package otp

import "testing"

func TestBuildURIReturnsErrorForInvalidType(t *testing.T) {
	uri, err := BuildURI("invalid", "SECRET", "acct", "issuer", "sha1", 0, 6, 30)
	if err == nil {
		t.Fatalf("expected error for invalid otp type")
	}
	if uri != "" {
		t.Fatalf("expected empty uri on error, got %q", uri)
	}
}

func TestBuildUriDoesNotPanicForInvalidType(t *testing.T) {
	if uri := BuildUri("invalid", "SECRET", "acct", "issuer", "sha1", 0, 6, 30); uri != "" {
		t.Fatalf("expected empty uri for invalid otp type, got %q", uri)
	}
}

func TestGenerateOTPReturnsErrorForInvalidInput(t *testing.T) {
	o := NewOTP("JBSWY3DPEHPK3PXP", 6, nil)
	if _, err := o.GenerateOTP(-1); err == nil {
		t.Fatal("expected error for negative otp input")
	}
}

func TestGenerateOTPDoesNotPanicForInvalidSecret(t *testing.T) {
	o := NewOTP("not-base32", 6, nil)
	if got := o.generateOTP(1); got != "" {
		t.Fatalf("expected empty otp for invalid secret, got %q", got)
	}
}
