package service

import "testing"

func TestEventMaskingMasksProtoAndJSONFields(t *testing.T) {
	fullMethod := "/ada.ADA/EnableMfa"
	protoData := `username:"admin" password:"secret" secret:"totp-secret" mfaCode:"123456" remark:"keep"`
	masked := eventMasking(fullMethod, protoData)

	for _, leaked := range []string{"secret", "totp-secret", "123456"} {
		if leaked != "secret" && contains(masked, leaked) {
			t.Fatalf("expected %q to be masked in %q", leaked, masked)
		}
	}
	if !contains(masked, `password:"***"`) || !contains(masked, `secret:"***"`) || !contains(masked, `mfaCode:"***"`) {
		t.Fatalf("expected sensitive proto fields to be masked, got %q", masked)
	}
	if !contains(masked, `remark:"keep"`) {
		t.Fatalf("expected non-sensitive field to remain, got %q", masked)
	}

	jsonData := `{"licenseKey":"abc","other":"keep"}`
	masked = eventMasking("/ada.ADA/UpdateLicense", jsonData)
	if contains(masked, "abc") || !contains(masked, `"licenseKey":"***"`) {
		t.Fatalf("expected JSON license key to be masked, got %q", masked)
	}
}

func TestEventMaskingMasksMetadataMapValues(t *testing.T) {
	data := `endpoint:"https://example.com" metadata:{key:"username" value:"admin"} metadata:{key:"password" value:"secret"}`
	masked := eventMasking("/ada.ADA/AddNotifyConf", data)

	if contains(masked, "admin") || contains(masked, "secret") {
		t.Fatalf("expected metadata values to be masked, got %q", masked)
	}
	if !contains(masked, `endpoint:"https://example.com"`) {
		t.Fatalf("expected non-metadata fields to remain, got %q", masked)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
