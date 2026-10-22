package fwmgr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

var ldapOperations = map[string]bool{
	"add": true, "delete": true, "modify": true, "modifydn": true,
	"search": true, "compare": true, "extended": true, "*": true,
}

var ldapScopes = map[string]bool{
	"": true, "base": true, "one level": true, "subtree": true,
}

// ValidateLDAPConf checks that content is a well-formed LDAP Firewall
// config.json before it is written. It rejects malformed JSON, a missing rules
// array, unknown fields (to catch typos that would silently drop a rule) and
// out-of-range enum values. On Windows the manager's own "/update" (which runs
// its "/validate") is the second gate; this is the fast local pre-check.
func ValidateLDAPConf(content []byte) error {
	var top struct {
		Rules   []json.RawMessage `json:"rules"`
		Debug   *string           `json:"debug"`
		LogPath *string           `json:"logPath"`
		Offsets json.RawMessage   `json:"offsets"` // injected by the manager; tolerated
	}
	if err := strictJSON(content, &top); err != nil {
		return fmt.Errorf("config.json: %w", err)
	}
	if top.Rules == nil {
		return fmt.Errorf("config.json: missing \"rules\" array")
	}
	if top.Debug != nil && *top.Debug != "on" && *top.Debug != "off" {
		return fmt.Errorf("debug %q must be on or off", *top.Debug)
	}
	for i, raw := range top.Rules {
		if err := validateLDAPRule(raw); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return nil
}

func validateLDAPRule(raw json.RawMessage) error {
	var r struct {
		Operations []string `json:"operations"`
		IPs        []string `json:"ips"`
		Users      []string `json:"users"`
		Groups     []string `json:"groups"`
		Action     *string  `json:"action"`
		Audit      *string  `json:"audit"`
		DN         *string  `json:"dn"`
		Attributes []string `json:"attributes"`
		OID        *string  `json:"oid"`
		Filter     *string  `json:"filter"`
		Scope      *string  `json:"scope"`
	}
	if err := strictJSON(raw, &r); err != nil {
		return err
	}
	for _, op := range r.Operations {
		if !ldapOperations[strings.ToLower(strings.TrimSpace(op))] {
			return fmt.Errorf("unknown operation %q", op)
		}
	}
	if r.Action != nil && *r.Action != "allow" && *r.Action != "block" {
		return fmt.Errorf("action %q must be allow or block", *r.Action)
	}
	if r.Audit != nil && *r.Audit != "on" && *r.Audit != "off" {
		return fmt.Errorf("audit %q must be on or off", *r.Audit)
	}
	if r.Scope != nil && !ldapScopes[strings.ToLower(strings.TrimSpace(*r.Scope))] {
		return fmt.Errorf("scope %q must be base, one level or subtree", *r.Scope)
	}
	return nil
}

func strictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}
