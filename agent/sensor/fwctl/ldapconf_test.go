package fwctl

import "testing"

func TestValidateLDAPConf(t *testing.T) {
	ok := [][]byte{
		[]byte(`{"rules":[{"operations":["search"],"attributes":["admincount"],"audit":"on"}]}`),
		[]byte(`{"rules":[{"operations":["*"],"action":"allow","audit":"on"}],"debug":"off"}`),
		[]byte(`{"rules":[{"operations":["modify"],"action":"block","scope":"subtree"}]}`),
		[]byte(`{"rules":[],"offsets":{"addRequest":1},"logPath":"C:\\x"}`),
	}
	for _, c := range ok {
		if err := ValidateLDAPConf(c); err != nil {
			t.Errorf("expected valid: %s -> %v", c, err)
		}
	}

	bad := map[string][]byte{
		"not json":   []byte(`{`),
		"no rules":   []byte(`{"debug":"on"}`),
		"bad op":     []byte(`{"rules":[{"operations":["reed"]}]}`),
		"bad action": []byte(`{"rules":[{"operations":["search"],"action":"deny"}]}`),
		"bad audit":  []byte(`{"rules":[{"operations":["search"],"audit":"yes"}]}`),
		"bad scope":  []byte(`{"rules":[{"operations":["search"],"scope":"everything"}]}`),
		"typo field": []byte(`{"rules":[{"operations":["search"],"atributes":["x"]}]}`),
		"bad debug":  []byte(`{"rules":[],"debug":"verbose"}`),
	}
	for name, c := range bad {
		if err := ValidateLDAPConf(c); err == nil {
			t.Errorf("expected invalid (%s): %s", name, c)
		}
	}
}
