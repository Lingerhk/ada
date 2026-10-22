package fwmgr

import "testing"

func TestProtectionApplied(t *testing.T) {
	cases := []struct {
		ids  []int
		want bool
	}{
		{[]int{1, 2, 1}, true},
		{[]int{2, 1}, false},
		{[]int{1}, true},
		{[]int{2}, false},
		{[]int{3, 3}, false},
		{nil, false},
		{[]int{3, 1, 2}, true},
	}
	for _, c := range cases {
		if got := protectionApplied(c.ids, 1, 2); got != c.want {
			t.Errorf("protectionApplied(%v)=%v want %v", c.ids, got, c.want)
		}
	}
}
