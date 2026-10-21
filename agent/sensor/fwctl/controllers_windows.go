//go:build windows

package fwctl

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// rpcFirewall / ldapFirewall service names as registered by the upstream
// managers.
const (
	rpcServiceName  = "RPC Firewall"
	ldapServiceName = "LDAP Firewall"
)

// runManager runs the firewall manager executable with a fixed argument vector
// (no shell), bounded by ctx, and returns its combined output.
func runManager(ctx context.Context, exePath string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, exePath, args...)
	cmd.Dir = dirOf(exePath)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return "."
}

func managerInstalled(exePath string) bool {
	_, err := os.Stat(exePath)
	return err == nil
}

// --- RPC Firewall -----------------------------------------------------------

type rpcFirewall struct {
	exePath  string
	confPath string
}

// NewRPCFirewall returns a Controller for the RPC Firewall, driving the manager
// at exePath and the RpcFw.conf at confPath.
func NewRPCFirewall(exePath, confPath string) Controller {
	return &rpcFirewall{exePath: exePath, confPath: confPath}
}

func (r *rpcFirewall) Name() string    { return "rpcfw" }
func (r *rpcFirewall) Installed() bool { return managerInstalled(r.exePath) }

func (r *rpcFirewall) Start(ctx context.Context) error {
	if out, err := runManager(ctx, r.exePath, "/start"); err != nil {
		return fmt.Errorf("rpcfw /start: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

func (r *rpcFirewall) Stop(ctx context.Context) error {
	if out, err := runManager(ctx, r.exePath, "/stop"); err != nil {
		return fmt.Errorf("rpcfw /stop: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

func (r *rpcFirewall) ApplyConfig(ctx context.Context, content []byte) error {
	return atomicApply(r.confPath, content, ValidateRPCConf, func() error {
		if out, err := runManager(ctx, r.exePath, "/update"); err != nil {
			return fmt.Errorf("rpcfw /update: %w (%s)", err, strings.TrimSpace(out))
		}
		return nil
	})
}

func (r *rpcFirewall) Status(ctx context.Context) (Status, error) {
	st := Status{Installed: r.Installed()}
	if !st.Installed {
		return st, nil
	}
	exists, running, err := serviceState(rpcServiceName)
	if err != nil {
		return st, err
	}
	st.Installed = st.Installed || exists
	st.Running = running
	if running {
		active, err := queryProtectionActive(ctx, rpcEventChannel, rpcProtectionAddedID, rpcProtectionRemovedID)
		if err == nil {
			st.ProtectionActive = active
		}
	}
	return st, nil
}

// --- LDAP Firewall ----------------------------------------------------------

type ldapFirewall struct {
	exePath  string
	confPath string
}

// NewLDAPFirewall returns a Controller for the LDAP Firewall, driving the
// manager at exePath and the config.json at confPath.
func NewLDAPFirewall(exePath, confPath string) Controller {
	return &ldapFirewall{exePath: exePath, confPath: confPath}
}

func (l *ldapFirewall) Name() string    { return "ldapfw" }
func (l *ldapFirewall) Installed() bool { return managerInstalled(l.exePath) }

func (l *ldapFirewall) Start(ctx context.Context) error {
	if out, err := runManager(ctx, l.exePath, "/start"); err != nil {
		return fmt.Errorf("ldapfw /start: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

func (l *ldapFirewall) Stop(ctx context.Context) error {
	if out, err := runManager(ctx, l.exePath, "/stop"); err != nil {
		return fmt.Errorf("ldapfw /stop: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

func (l *ldapFirewall) ApplyConfig(ctx context.Context, content []byte) error {
	return atomicApply(l.confPath, content, ValidateLDAPConf, func() error {
		// /update runs the manager's own /validate, injects the refreshed
		// config over the named pipe, and returns non-zero on failure, which
		// triggers rollback in atomicApply.
		if out, err := runManager(ctx, l.exePath, "/update"); err != nil {
			return fmt.Errorf("ldapfw /update: %w (%s)", err, strings.TrimSpace(out))
		}
		return nil
	})
}

func (l *ldapFirewall) Status(ctx context.Context) (Status, error) {
	st := Status{Installed: l.Installed()}
	if !st.Installed {
		return st, nil
	}
	exists, running, err := serviceState(ldapServiceName)
	if err != nil {
		return st, err
	}
	st.Installed = st.Installed || exists
	st.Running = running
	if running {
		active, err := queryProtectionActive(ctx, ldapEventChannel, ldapProtectionAddedID, ldapProtectionRemovedID)
		if err == nil {
			st.ProtectionActive = active
		}
	}
	return st, nil
}
