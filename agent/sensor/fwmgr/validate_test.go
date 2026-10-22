package fwmgr

import "testing"

func TestValidateRPCConf(t *testing.T) {
	valid := []string{
		"fw:action:allow audit:true \n",
		"fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 opnum:3 action:block\nflt:uuid:abc action:allow\n",
		"fw:addr:10.0.0.0/8 prot:ncacn_np action:block audit:true\n",
		"fw:addr:2001:db8::1 action:block\n",
	}
	for _, c := range valid {
		if err := ValidateRPCConf([]byte(c)); err != nil {
			t.Errorf("valid rejected: %q -> %v", c, err)
		}
	}
	invalid := map[string]string{
		"empty":       "\n   \n",
		"no scope":    "action:allow\n",
		"bad action":  "fw:action:permit\n",
		"bad audit":   "fw:audit:yes\n",
		"bad opnum":   "fw:opnum:x action:allow\n",
		"bad addr":    "fw:addr:10.0.0.999 action:allow\n",
		"bad prot":    "fw:prot:smoke action:allow\n",
		"unknown key": "fw:color:red\n",
		"bad token":   "fw:actionallow\n",
		"empty rule":  "fw:\n",
	}
	for name, c := range invalid {
		if err := ValidateRPCConf([]byte(c)); err == nil {
			t.Errorf("invalid accepted (%s): %q", name, c)
		}
	}
}

func TestValidateLDAPConf(t *testing.T) {
	valid := []string{
		`{"rules":[{"operations":["search"],"attributes":["admincount"],"audit":"on"}]}`,
		`{"rules":[{"operations":["*"],"action":"allow","audit":"on"}],"debug":"off"}`,
		`{"rules":[{"operations":["modify"],"action":"block","scope":"one level"}]}`,
		`{"rules":[],"offsets":{"addRequest":1},"logPath":"C:\\x"}`,
	}
	for _, c := range valid {
		if err := ValidateLDAPConf([]byte(c)); err != nil {
			t.Errorf("valid rejected: %s -> %v", c, err)
		}
	}
	invalid := map[string]string{
		"broken json": `{`,
		"no rules":    `{"debug":"on"}`,
		"bad op":      `{"rules":[{"operations":["reed"]}]}`,
		"bad action":  `{"rules":[{"operations":["search"],"action":"deny"}]}`,
		"bad audit":   `{"rules":[{"operations":["search"],"audit":"loud"}]}`,
		"bad scope":   `{"rules":[{"operations":["search"],"scope":"galaxy"}]}`,
		"typo field":  `{"rules":[{"operations":["search"],"atributes":["x"]}]}`,
		"bad debug":   `{"rules":[],"debug":"verbose"}`,
	}
	for name, c := range invalid {
		if err := ValidateLDAPConf([]byte(c)); err == nil {
			t.Errorf("invalid accepted (%s): %s", name, c)
		}
	}
}
