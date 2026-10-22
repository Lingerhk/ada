package sigma_test

import (
	"path/filepath"
	"testing"

	"ada/engine/sigma"
	"ada/infra/datamodels"
)

func loadWinlog(t *testing.T) *sigma.Ruleset {
	t.Helper()
	rs, err := sigma.NewRuleset(sigma.Config{
		Directory:       []string{filepath.Clean(filepath.Join("..", "rules", "winlog"))},
		FailOnRuleParse: true,
		FailOnYamlParse: true,
	}, nil)
	if err != nil {
		t.Fatalf("parse winlog rules: %v", err)
	}
	return rs
}

func matched(rs *sigma.Ruleset, ev datamodels.Map) map[string]bool {
	out := map[string]bool{}
	results, _ := rs.EvalAll(ev)
	for _, r := range results {
		out[r.ID] = true
	}
	return out
}

// Mock events mirror the sensor's winevt output for the firewall channels:
// Channel + EventID + rendered Message (the firewalls log with legacy insert
// strings, so Message is the only reliable field).
func TestFirewallRules(t *testing.T) {
	rs := loadWinlog(t)

	cases := []struct {
		name string
		ev   datamodels.Map
		hit  []string
		miss []string
	}{
		{
			name: "RPCFW protection removed fires 0336",
			ev:   datamodels.Map{"Channel": "RPCFW", "EventID": 2, "Message": "RPC Firewall protection removed.\n\tProcess ID:\t712"},
			hit:  []string{"winlog-0336"},
			miss: []string{"winlog-0337", "winlog-0338", "winlog-0339"},
		},
		{
			name: "RPCFW protection added is not an alert",
			ev:   datamodels.Map{"Channel": "RPCFW", "EventID": 1, "Message": "RPC Firewall protection added."},
			miss: []string{"winlog-0336", "winlog-0337"},
		},
		{
			name: "RPCFW DRSUAPI call fires 0337",
			ev:   datamodels.Map{"Channel": "RPCFW", "EventID": 3, "Message": "An RPC server function was called.\n\tClient Network Address:\t10.10.20.55\n\tInterfaceUuid:\te3514235-4b06-11d1-ab04-00c04fc2dcd2\n\tOpNum:\t\t3"},
			hit:  []string{"winlog-0337"},
			miss: []string{"winlog-0336"},
		},
		{
			name: "RPCFW DRSUAPI UUID upper-case still fires 0337 (case-insensitive)",
			ev:   datamodels.Map{"Channel": "RPCFW", "EventID": 3, "Message": "\tInterfaceUuid:\tE3514235-4B06-11D1-AB04-00C04FC2DCD2"},
			hit:  []string{"winlog-0337"},
		},
		{
			name: "RPCFW call to another interface does not fire 0337",
			ev:   datamodels.Map{"Channel": "RPCFW", "EventID": 3, "Message": "\tInterfaceUuid:\t12345678-1234-abcd-ef00-0123456789ab"},
			miss: []string{"winlog-0337"},
		},
		{
			name: "LDAPFW protection removed fires 0338",
			ev:   datamodels.Map{"Channel": "LDAPFW", "EventID": 258, "Message": "LDAP Firewall protection removed."},
			hit:  []string{"winlog-0338"},
			miss: []string{"winlog-0336", "winlog-0339"},
		},
		{
			name: "LDAPFW admincount search fires 0339",
			ev:   datamodels.Map{"Channel": "LDAPFW", "EventID": 263, "Message": "An LDAP Search was called.\n\tAttributes: name, admincount, memberof"},
			hit:  []string{"winlog-0339"},
			miss: []string{"winlog-0338"},
		},
		{
			name: "LDAPFW camel-case servicePrincipalName fires 0339",
			ev:   datamodels.Map{"Channel": "LDAPFW", "EventID": 263, "Message": "\tAttributes: servicePrincipalName"},
			hit:  []string{"winlog-0339"},
		},
		{
			name: "LDAPFW Shadow Credentials attribute fires 0339",
			ev:   datamodels.Map{"Channel": "LDAPFW", "EventID": 261, "Message": "An LDAP Modify was called.\n\tAttributes: msDS-KeyCredentialLink"},
			hit:  []string{"winlog-0339"},
		},
		{
			name: "LDAPFW LAPS attribute fires 0339",
			ev:   datamodels.Map{"Channel": "LDAPFW", "EventID": 263, "Message": "\tAttributes: ms-Mcs-AdmPwd"},
			hit:  []string{"winlog-0339"},
		},
		{
			name: "LDAPFW ordinary search is not an alert",
			ev:   datamodels.Map{"Channel": "LDAPFW", "EventID": 263, "Message": "\tAttributes: name, mail, department"},
			miss: []string{"winlog-0338", "winlog-0339"},
		},
		{
			name: "same indicators on another channel do not fire firewall rules",
			ev:   datamodels.Map{"Channel": "Application", "EventID": 2, "Message": "e3514235-4b06-11d1-ab04-00c04fc2dcd2 admincount"},
			miss: []string{"winlog-0336", "winlog-0337", "winlog-0338", "winlog-0339"},
		},
	}

	for _, c := range cases {
		got := matched(rs, c.ev)
		for _, id := range c.hit {
			if !got[id] {
				t.Errorf("%s: expected %s to match", c.name, id)
			}
		}
		for _, id := range c.miss {
			if got[id] {
				t.Errorf("%s: %s must not match", c.name, id)
			}
		}
	}
}
