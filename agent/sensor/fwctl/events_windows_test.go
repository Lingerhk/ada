//go:build windows

package fwctl

import "testing"

func TestParseEventIDs(t *testing.T) {
	xml := `<Event><System><EventID Qualifiers="0">2</EventID></System></Event>` +
		`<Event><System><EventID>1</EventID></System></Event>`
	ids := parseEventIDs(xml)
	if len(ids) != 2 || ids[0] != 2 || ids[1] != 1 {
		t.Fatalf("got %v", ids)
	}
}
