//go:build windows

package fwmgr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// NewRPC builds a Manager for the RPC Firewall using the real Windows System.
func NewRPC(exe, conf string) *Manager { return New(RPCSpec(exe, conf), windowsSystem{}) }

// NewLDAP builds a Manager for the LDAP Firewall using the real Windows System.
func NewLDAP(exe, conf string) *Manager { return New(LDAPSpec(exe, conf), windowsSystem{}) }

// windowsSystem is the production System backed by the Windows service manager,
// process execution and the event log.
type windowsSystem struct{}

func (windowsSystem) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (windowsSystem) RunManager(ctx context.Context, exe string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, exe, args...)
	if i := strings.LastIndexAny(exe, `\/`); i >= 0 {
		cmd.Dir = exe[:i] // managers resolve their config file next to the exe
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (windowsSystem) ServiceRunning(name string) (exists, running bool, err error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, false, err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return false, false, nil // not installed is not an error for a status check
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return true, false, err
	}
	return true, st.State == svc.Running, nil
}

func (windowsSystem) RecentEventIDs(ctx context.Context, channel string, wantIDs ...int) ([]int, error) {
	if len(wantIDs) == 0 {
		return nil, nil
	}
	terms := make([]string, len(wantIDs))
	for i, id := range wantIDs {
		terms[i] = fmt.Sprintf("EventID=%d", id)
	}
	query := "*[System[(" + strings.Join(terms, " or ") + ")]]"
	cmd := exec.CommandContext(ctx, "wevtutil.exe", "qe", channel,
		"/q:"+query, "/c:10", "/rd:true", "/f:xml")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("query %s events: %w", channel, err)
	}
	return parseEventIDs(string(out)), nil
}

// parseEventIDs extracts <EventID>N</EventID> values in document order from the
// XML rendered by "wevtutil qe ... /f:xml". With /rd:true the newest event is
// rendered first, which is the order protectionApplied expects.
func parseEventIDs(xmlDoc string) []int {
	var ids []int
	for {
		i := strings.Index(xmlDoc, "<EventID")
		if i < 0 {
			break
		}
		xmlDoc = xmlDoc[i:]
		gt := strings.IndexByte(xmlDoc, '>')
		end := strings.Index(xmlDoc, "</EventID>")
		if gt < 0 || end < 0 || gt > end {
			break
		}
		if v, err := strconv.Atoi(strings.TrimSpace(xmlDoc[gt+1 : end])); err == nil {
			ids = append(ids, v)
		}
		xmlDoc = xmlDoc[end+len("</EventID>"):]
	}
	return ids
}
