package fwctl

import "testing"

func TestProtectionActiveFromEvents(t *testing.T) {
	cases := []struct {
		name string
		ids  []int
		want bool
	}{
		{"added most recent", []int{1, 2, 1}, true},
		{"removed most recent", []int{2, 1, 2}, false},
		{"only added", []int{1}, true},
		{"only removed", []int{2}, false},
		{"none", []int{3, 3}, false},
		{"empty", nil, false},
		{"call events ignored until add", []int{3, 3, 1, 2}, true},
	}
	for _, c := range cases {
		if got := protectionActiveFromEvents(c.ids, rpcProtectionAddedID, rpcProtectionRemovedID); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
