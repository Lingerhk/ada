package sanitize

import "testing"

func TestValidateAccountName(t *testing.T) {
	valid := []string{"alice", "svc_backup", "DC01$", "john.doe", "张三", "a-b"}
	for _, v := range valid {
		if err := ValidateAccountName(v); err != nil {
			t.Errorf("expected %q to be valid, got %v", v, err)
		}
	}

	invalid := []string{
		"",
		"alice; Remove-Item C:\\ -Recurse",
		"bob' ; whoami ; '",
		"$(whoami)",
		"a b",
		"corp\\alice",
		"alice,bob",
		"`whoami`",
		"a|b",
		string(make([]byte, maxAccountNameLen+1)),
	}
	for _, v := range invalid {
		if err := ValidateAccountName(v); err == nil {
			t.Errorf("expected %q to be rejected", v)
		}
	}
}

func TestValidateIPOrCIDR(t *testing.T) {
	cases := map[string]string{
		"10.0.0.1":      "10.0.0.1",
		" 10.0.0.1 ":    "10.0.0.1",
		"10.0.0.0/8":    "10.0.0.0/8",
		"10.0.0.7/24":   "10.0.0.0/24",
		"2001:db8::1":   "2001:db8::1",
		"2001:db8::/32": "2001:db8::/32",
	}
	for in, want := range cases {
		got, err := ValidateIPOrCIDR(in)
		if err != nil || got != want {
			t.Errorf("ValidateIPOrCIDR(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	invalid := []string{"", "1.2.3", "10.0.0.1; whoami", "fe80::1%eth0", "any", "10.0.0.1,10.0.0.2"}
	for _, v := range invalid {
		if _, err := ValidateIPOrCIDR(v); err == nil {
			t.Errorf("expected %q to be rejected", v)
		}
	}
}

func TestPowerShellQuote(t *testing.T) {
	if got := PowerShellQuote("abc"); got != "'abc'" {
		t.Fatalf("got %s", got)
	}
	if got := PowerShellQuote("a'b"); got != "'a''b'" {
		t.Fatalf("got %s", got)
	}
}
