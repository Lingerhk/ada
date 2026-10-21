package fwctl

import "testing"

func TestValidateRPCConf(t *testing.T) {
	ok := [][]byte{
		[]byte("fw:action:allow audit:true \n"),
		[]byte("fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 opnum:3 action:block\nflt:uuid:12345678 action:allow\n"),
		[]byte("fw:addr:10.0.0.0/8 action:block audit:true\nfw:prot:ncacn_np action:allow\n"),
	}
	for _, c := range ok {
		if err := ValidateRPCConf(c); err != nil {
			t.Errorf("expected valid: %q -> %v", c, err)
		}
	}

	bad := map[string][]byte{
		"empty":       []byte("   \n\n"),
		"no prefix":   []byte("action:allow audit:true\n"),
		"bad action":  []byte("fw:action:permit\n"),
		"bad audit":   []byte("fw:audit:yes\n"),
		"bad opnum":   []byte("fw:opnum:three action:block\n"),
		"bad addr":    []byte("fw:addr:999.1 action:block\n"),
		"bad prot":    []byte("fw:prot:carrierpigeon action:block\n"),
		"unknown key": []byte("fw:frobnicate:1 action:allow\n"),
		"bad token":   []byte("fw:actionallow\n"),
	}
	for name, c := range bad {
		if err := ValidateRPCConf(c); err == nil {
			t.Errorf("expected invalid (%s): %q", name, c)
		}
	}
}
