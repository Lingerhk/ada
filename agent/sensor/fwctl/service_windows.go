//go:build windows

package fwctl

import (
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceState reports whether the named Windows service exists and whether it
// is currently running. A missing service is (false, false, nil).
func serviceState(name string) (exists, running bool, err error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, false, err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		// Not installed (or not visible) — not an error for a status check.
		return false, false, nil
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return true, false, err
	}
	return true, st.State == svc.Running, nil
}
