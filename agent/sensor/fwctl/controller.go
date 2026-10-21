// Package fwctl is the ADAegis sensor's control layer for the bundled
// RPC Firewall and LDAP Firewall. It replaces the previous approach of
// shelling out to the managers and parsing their text output / querying raw
// service state: configuration is validated and applied atomically with
// rollback, and "is protection actually active" is derived from the
// firewalls' own Windows event log instead of merely "the service is running".
//
// The hooking DLLs remain the upstream native components; fwctl only drives
// their managers and services and reads their telemetry.
package fwctl

import "context"

// Status is a point-in-time view of one firewall.
type Status struct {
	// Installed is true when the firewall's manager/service is present.
	Installed bool
	// Running is true when its Windows service is in the running state.
	Running bool
	// ProtectionActive is true when the event log shows protection is applied
	// (RPCFW: a protect-added without a later removed; LDAPFW: likewise).
	// It distinguishes "service up" from "actually protecting".
	ProtectionActive bool
}

// Controller drives one firewall. Implementations are Windows-specific; the
// non-Windows build provides stubs so the package compiles everywhere.
type Controller interface {
	// Name is the short plugin name ("rpcfw" / "ldapfw").
	Name() string
	// Installed reports whether the firewall is deployed on this host.
	Installed() bool
	// Start applies protection (installs filters / injects the hook DLL via
	// the manager) and starts the service.
	Start(ctx context.Context) error
	// Stop removes protection and stops the service.
	Stop(ctx context.Context) error
	// ApplyConfig validates content, writes it atomically and asks the
	// firewall to reload; on reload failure it rolls back.
	ApplyConfig(ctx context.Context, content []byte) error
	// Status reports installed / running / protection-active.
	Status(ctx context.Context) (Status, error)
}
