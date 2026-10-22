// Package fwmgr is the ADAegis sensor's interaction layer for the bundled
// RPC Firewall and LDAP Firewall. It drives their native managers and Windows
// services from Go: configuration pushed by the backend is validated and
// written atomically with rollback, and whether protection is actually in
// effect is derived from the firewalls' own event log rather than from "the
// service process is alive".
//
// The scope is deliberately the manager/service boundary only. The injection
// and hooking DLLs remain the upstream native components; fwmgr never touches
// injection, lsass or symbol resolution.
package fwmgr

import (
	"context"
	"fmt"
)

// System is the set of operating-system operations a Manager needs. It is an
// interface so the control flow can be driven by a fake in tests on any OS;
// the real implementation is Windows-only (see system_windows.go).
type System interface {
	// RunManager runs the firewall manager executable at exe with a fixed
	// argument vector (no shell), bounded by ctx, returning combined output.
	RunManager(ctx context.Context, exe string, args ...string) (output string, err error)
	// ServiceRunning reports whether the named Windows service exists and is
	// currently in the running state.
	ServiceRunning(name string) (exists, running bool, err error)
	// RecentEventIDs returns the event IDs among wantIDs found in channel,
	// most recent first.
	RecentEventIDs(ctx context.Context, channel string, wantIDs ...int) ([]int, error)
	// Exists reports whether path exists on disk.
	Exists(path string) bool
}

// Spec is the fixed description of one firewall: how to find it, control it and
// read its state.
type Spec struct {
	Name      string             // short plugin name, e.g. "rpcfw"
	Service   string             // Windows service name, e.g. "RPC Firewall"
	Exe       string             // full path to the manager executable
	Conf      string             // full path to the on-disk configuration file
	Channel   string             // event-log channel the firewall writes to
	AddedID   int                // event ID logged when protection is applied
	RemovedID int                // event ID logged when protection is removed
	Validate  func([]byte) error // configuration validator
}

// Status is a point-in-time view of one firewall.
type Status struct {
	Installed bool // the manager executable is present
	Running   bool // the Windows service is running
	Protected bool // the event log shows protection is currently applied
}

// Manager drives one firewall through a System.
type Manager struct {
	spec Spec
	sys  System
}

// New builds a Manager for spec backed by sys.
func New(spec Spec, sys System) *Manager { return &Manager{spec: spec, sys: sys} }

// Name is the short plugin name.
func (m *Manager) Name() string { return m.spec.Name }

// Installed reports whether the firewall manager is deployed on this host.
func (m *Manager) Installed() bool { return m.sys.Exists(m.spec.Exe) }

func (m *Manager) run(ctx context.Context, arg string) error {
	out, err := m.sys.RunManager(ctx, m.spec.Exe, arg)
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", m.spec.Name, arg, err, trim(out))
	}
	return nil
}

// Start applies protection and starts the service ("/start").
func (m *Manager) Start(ctx context.Context) error { return m.run(ctx, "/start") }

// Stop removes protection and stops the service ("/stop").
func (m *Manager) Stop(ctx context.Context) error { return m.run(ctx, "/stop") }

// ApplyConfig validates content, writes it to the firewall's config file
// atomically, tells the firewall to reload ("/update") and rolls the file back
// to its previous content if the reload is rejected.
func (m *Manager) ApplyConfig(ctx context.Context, content []byte) error {
	return applyConfig(m.spec.Conf, content, m.spec.Validate, func() error {
		return m.run(ctx, "/update")
	})
}

// ProtectionActive reports whether protection is currently applied: the
// service must be running and the most recent protect/unprotect event must be
// a protect. When the service is not running it is false with no error.
func (m *Manager) ProtectionActive(ctx context.Context) (bool, error) {
	_, running, err := m.sys.ServiceRunning(m.spec.Service)
	if err != nil {
		return false, fmt.Errorf("%s service state: %w", m.spec.Name, err)
	}
	if !running {
		return false, nil
	}
	ids, err := m.sys.RecentEventIDs(ctx, m.spec.Channel, m.spec.AddedID, m.spec.RemovedID)
	if err != nil {
		return false, fmt.Errorf("%s protection state: %w", m.spec.Name, err)
	}
	return protectionApplied(ids, m.spec.AddedID, m.spec.RemovedID), nil
}

// Status reports installed / running / protected.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	st := Status{Installed: m.Installed()}
	if !st.Installed {
		return st, nil
	}
	exists, running, err := m.sys.ServiceRunning(m.spec.Service)
	if err != nil {
		return st, fmt.Errorf("%s service state: %w", m.spec.Name, err)
	}
	st.Installed = st.Installed || exists
	st.Running = running
	if !running {
		return st, nil
	}
	ids, err := m.sys.RecentEventIDs(ctx, m.spec.Channel, m.spec.AddedID, m.spec.RemovedID)
	if err != nil {
		return st, fmt.Errorf("%s protection state: %w", m.spec.Name, err)
	}
	st.Protected = protectionApplied(ids, m.spec.AddedID, m.spec.RemovedID)
	return st, nil
}
