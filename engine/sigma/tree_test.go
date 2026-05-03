package sigma

import (
	"encoding/json"
	"testing"

	"ada/infra/datamodels"

	"gopkg.in/yaml.v3"
)

func TestTreeParse(t *testing.T) {
	for _, c := range parseTestCases {
		var rule Rule
		if err := yaml.Unmarshal([]byte(c.Rule), &rule); err != nil {
			t.Fatalf("tree parse case %d failed to unmarshal yaml, %s", c.ID, err)
		}
		p, err := NewTree(RuleHandle{Rule: rule, NoCollapseWS: c.noCollapseWSNeg})
		if err != nil {
			t.Fatalf("tree parse case %d failed: %s", c.ID, err)
		}
		// Positive cases
		for i, c2 := range c.Pos {
			var obj datamodels.Map
			if err := json.Unmarshal([]byte(c2), &obj); err != nil {
				t.Fatalf("rule parser case %d positive case %d json unmarshal error %s", c.ID, i, err)
			}
			m, _ := p.Match(obj)
			if !m {
				t.Fatalf("rule parser case %d positive case %d did not match", c.ID, i)
			}
		}
		// Negative cases
		for i, c2 := range c.Neg {
			var obj datamodels.Map
			if err := json.Unmarshal([]byte(c2), &obj); err != nil {
				t.Fatalf("rule parser case %d positive case %d json unmarshal error %s", c.ID, i, err)
			}
			m, _ := p.Match(obj)
			if m {
				t.Fatalf("rule parser case %d negative case %d matched", c.ID, i)
			}
		}
	}
}

func TestLogsourceUnmarshalSupportsScalarAndMapping(t *testing.T) {
	var scalar Rule
	if err := yaml.Unmarshal([]byte(`logsource: winlog`), &scalar); err != nil {
		t.Fatalf("scalar logsource failed to unmarshal: %v", err)
	}
	if scalar.Logsource.Product != "winlog" {
		t.Fatalf("scalar logsource product = %q, want winlog", scalar.Logsource.Product)
	}

	var mapping Rule
	if err := yaml.Unmarshal([]byte(`logsource:
  product: windows
  category: process_creation
  service: security
  definition: test
`), &mapping); err != nil {
		t.Fatalf("mapping logsource failed to unmarshal: %v", err)
	}
	if mapping.Logsource.Product != "windows" || mapping.Logsource.Category != "process_creation" ||
		mapping.Logsource.Service != "security" || mapping.Logsource.Definition != "test" {
		t.Fatalf("mapping logsource decoded incorrectly: %#v", mapping.Logsource)
	}
}

func TestBundledScalarLogsourceRuleParses(t *testing.T) {
	var rule Rule
	raw := `title: Win Login Succeeded
id: winlog-0000-0001
tags:
  - TA0007
logsource: winlog
detection:
  selection1:
    EventID: 4624
    LogonType: 3
    LogonProcessName: "Kerberos"
  filter1:
    IpAddress:
      - "::1"
      - "fe80"
      - "127.0.0.1"
  filter2:
    TargetUserSid|contains:
      - "S-1-5-18"
      - "S-1-5-90-0-"
  filter3:
    TargetUserName|endswith: "$"
  condition: selection1 and not filter1 and not filter2 and not filter3
fields:
  - "Hostname"
unique_fields:
  - "Hostname"
level: info
`
	if err := yaml.Unmarshal([]byte(raw), &rule); err != nil {
		t.Fatalf("rule failed to unmarshal: %v", err)
	}
	if _, err := NewTree(RuleHandle{Rule: rule}); err != nil {
		t.Fatalf("rule failed to parse tree: %v", err)
	}
}

func TestBundledWinlogRulesetKeepsCoreRuleAvailable(t *testing.T) {
	ruleset, err := NewRuleset(Config{Directory: []string{"../rules/winlog"}}, nil)
	if err != nil {
		t.Fatalf("ruleset failed to load: %v", err)
	}
	if ruleset.GetRule("winlog-0000-0001") == nil {
		t.Fatalf("core winlog rule is unavailable; total=%d ok=%d failed=%d unsupported=%d",
			ruleset.Total, ruleset.Ok, ruleset.Failed, ruleset.Unsupported)
	}
}

func TestLegacyKeyValueDetectionParses(t *testing.T) {
	raw := `id: winlog-legacy-kv
title: Legacy key value rule
tags:
  - TA0007
logsource: winlog
detection:
  condition: selection1 and not filter1
  selection1:
    - - key: key
        value: EventID
      - key: value
        value: 4624
    - - key: key
        value: LogonProcessName
      - key: value
        value: Kerberos
  filter1:
    - - key: value
        value:
          - "::1"
          - "127.0.0.1"
      - key: key
        value: IpAddress
fields:
  - Hostname
unique_fields:
  - Hostname
level: info
`
	rule, err := RuleFromYAML([]byte(raw))
	if err != nil {
		t.Fatalf("legacy key/value rule failed to unmarshal: %v", err)
	}
	tree, err := NewTree(RuleHandle{Rule: rule})
	if err != nil {
		t.Fatalf("legacy key/value rule failed to parse tree: %v", err)
	}
	matched, applicable := tree.Match(datamodels.Map{
		"EventID":          4624,
		"LogonProcessName": "Kerberos",
		"IpAddress":        "10.0.0.8",
	})
	if !matched || !applicable {
		t.Fatalf("legacy key/value rule did not match")
	}
}

// we should probably add an alternative to this benchmark to include noCollapseWS on or off (we collapse by default now)
func benchmarkCase(b *testing.B, rawRule, rawEvent string) {
	var rule Rule
	if err := yaml.Unmarshal([]byte(parseTestCases[0].Rule), &rule); err != nil {
		b.Fail()
	}
	p, err := NewTree(RuleHandle{Rule: rule})
	if err != nil {
		b.Fail()
	}
	var event datamodels.Map
	if err := json.Unmarshal([]byte(parseTestCases[0].Pos[0]), &event); err != nil {
		b.Fail()
	}
	for i := 0; i < b.N; i++ {
		p.Match(event)
	}
}

func BenchmarkTreePositive0(b *testing.B) {
	benchmarkCase(b, parseTestCases[0].Rule, parseTestCases[0].Pos[0])
}

func BenchmarkTreePositive1(b *testing.B) {
	benchmarkCase(b, parseTestCases[1].Rule, parseTestCases[1].Pos[0])
}

func BenchmarkTreePositive2(b *testing.B) {
	benchmarkCase(b, parseTestCases[2].Rule, parseTestCases[2].Pos[0])
}

func BenchmarkTreePositive3(b *testing.B) {
	benchmarkCase(b, parseTestCases[3].Rule, parseTestCases[3].Pos[0])
}

func BenchmarkTreePositive4(b *testing.B) {
	benchmarkCase(b, parseTestCases[4].Rule, parseTestCases[4].Pos[0])
}

func BenchmarkTreePositive5(b *testing.B) {
	benchmarkCase(b, parseTestCases[5].Rule, parseTestCases[6].Pos[0])
}

func BenchmarkTreePositive6(b *testing.B) {
	benchmarkCase(b, parseTestCases[6].Rule, parseTestCases[6].Pos[0])
}

func BenchmarkTreeNegative0(b *testing.B) {
	benchmarkCase(b, parseTestCases[0].Rule, parseTestCases[0].Neg[0])
}

func BenchmarkTreeNegative1(b *testing.B) {
	benchmarkCase(b, parseTestCases[1].Rule, parseTestCases[1].Neg[0])
}

func BenchmarkTreeNegative2(b *testing.B) {
	benchmarkCase(b, parseTestCases[2].Rule, parseTestCases[2].Neg[0])
}

func BenchmarkTreeNegative3(b *testing.B) {
	benchmarkCase(b, parseTestCases[3].Rule, parseTestCases[3].Neg[0])
}

func BenchmarkTreeNegative4(b *testing.B) {
	benchmarkCase(b, parseTestCases[4].Rule, parseTestCases[4].Neg[0])
}

func BenchmarkTreeNegative5(b *testing.B) {
	benchmarkCase(b, parseTestCases[5].Rule, parseTestCases[6].Neg[0])
}

func BenchmarkTreeNegative6(b *testing.B) {
	benchmarkCase(b, parseTestCases[6].Rule, parseTestCases[6].Neg[0])
}
