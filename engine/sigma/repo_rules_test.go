package sigma_test

import (
	"ada/engine/flow"
	"ada/engine/sigma"
	"ada/infra/datamodels"
	"path/filepath"
	"testing"
)

func TestRepoRulesParse(t *testing.T) {
	rulesDir := filepath.Clean(filepath.Join("..", "rules"))
	flowDir := filepath.Join(rulesDir, "flow")
	winlogDir := filepath.Join(rulesDir, "winlog")
	pktlogDir := filepath.Join(rulesDir, "pktlog")

	flowFiles, err := flow.NewRuleFileList([]string{flowDir})
	if err != nil {
		t.Fatalf("list flow rules: %v", err)
	}
	flowRules, err := flow.NewRuleList(flowFiles)
	if err != nil {
		t.Fatalf("parse flow rules: %v", err)
	}

	sigmaExtFields := make(map[string][]string)
	for _, rule := range flowRules {
		for sigmaID, fields := range rule.ExtFields {
			sigmaExtFields[sigmaID] = append(sigmaExtFields[sigmaID], fields...)
		}
	}

	winlogRules, err := sigma.NewRuleset(sigma.Config{
		Directory:       []string{winlogDir},
		FailOnRuleParse: true,
		FailOnYamlParse: true,
		ExtractFields:   sigmaExtFields,
	}, nil)
	if err != nil {
		t.Fatalf("parse winlog rules: %v", err)
	}
	if winlogRules.Failed != 0 || winlogRules.Unsupported != 0 {
		t.Fatalf("winlog rules failed=%d unsupported=%d", winlogRules.Failed, winlogRules.Unsupported)
	}

	pktlogRules, err := sigma.NewRuleset(sigma.Config{
		Directory:       []string{pktlogDir},
		FailOnRuleParse: true,
		FailOnYamlParse: true,
		ExtractFields:   sigmaExtFields,
	}, nil)
	if err != nil {
		t.Fatalf("parse pktlog rules: %v", err)
	}
	if pktlogRules.Failed != 0 || pktlogRules.Unsupported != 0 {
		t.Fatalf("pktlog rules failed=%d unsupported=%d", pktlogRules.Failed, pktlogRules.Unsupported)
	}

	for _, rule := range flowRules {
		for _, sigmaID := range rule.Detection.SigmaRules {
			if winlogRules.GetRule(sigmaID) == nil && pktlogRules.GetRule(sigmaID) == nil {
				t.Fatalf("flow rule %s references missing sigma rule %s", rule.ID, sigmaID)
			}
		}
	}
}

func TestGeneratedWinlogRuleMockEval(t *testing.T) {
	winlogDir := filepath.Clean(filepath.Join("..", "rules", "winlog"))
	winlogRules, err := sigma.NewRuleset(sigma.Config{
		Directory:       []string{winlogDir},
		FailOnRuleParse: true,
		FailOnYamlParse: true,
	}, nil)
	if err != nil {
		t.Fatalf("parse winlog rules: %v", err)
	}

	event := datamodels.Map{
		"Hostname":    "dc01.test.local",
		"EventID":     4768,
		"Status":      "0x0",
		"ServiceSid":  "S-1-5-21-1111111111-2222222222-3333333333-502",
		"PreAuthType": "0",
		"IpAddress":   "192.168.56.20",
	}

	results, ok := winlogRules.EvalAll(event)
	if !ok {
		t.Fatalf("expected generated AS-REP Roasting rule to match mock event")
	}
	for _, result := range results {
		if result.ID == "winlog-0036" {
			return
		}
	}
	t.Fatalf("expected winlog-0036 in results, got %#v", results)
}
