package datamodels

import (
	"strings"
	"testing"
)

func TestMapKeywordsIncludesScalarValuesAndRawJSON(t *testing.T) {
	event := Map{
		"EventData": `\ntds.dit`,
		"Nested": map[string]any{
			"CommandLine": "ntdsutil ifm create full",
		},
		"EventID": 325,
	}

	keywords, ok := event.Keywords()
	if !ok {
		t.Fatal("expected keyword extraction to be applicable")
	}

	joined := strings.Join(keywords, "\n")
	for _, want := range []string{`\ntds.dit`, "ntdsutil ifm create full", "325", "EventData"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected keyword output to contain %q, got %#v", want, keywords)
		}
	}
}
