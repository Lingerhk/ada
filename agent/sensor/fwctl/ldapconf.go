package fwctl

import (
	"encoding/json"
	"fmt"
)

// knownLDAPOperations are the LDAP operation names the firewall understands.
// An unknown value is upstream silently coerced to "any", which would widen a
// rule in a way the operator did not intend, so we treat it as an error.
var knownLDAPOperations = map[string]bool{
	"add": true, "delete": true, "modify": true, "modifydn": true,
	"search": true, "compare": true, "extended": true, "*": true,
}

var knownLDAPScopes = map[string]bool{
	"": true, "base": true, "one level": true, "subtree": true,
}

// ldapConfig mirrors the parts of config.json that the LDAP Firewall reads.
// Unknown top-level keys are tolerated (upstream ignores them); the "offsets"
// block is injected by the manager at apply time and is not validated here.
type ldapConfig struct {
	Rules []ldapRule `json:"rules"`
	Debug *string    `json:"debug,omitempty"`
}

type ldapRule struct {
	Operations []string `json:"operations"`
	IPs        []string `json:"ips,omitempty"`
	Users      []string `json:"users,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	Action     *string  `json:"action,omitempty"`
	Audit      *string  `json:"audit,omitempty"`
	DN         *string  `json:"dn,omitempty"`
	Attributes []string `json:"attributes,omitempty"`
	OID        *string  `json:"oid,omitempty"`
	Filter     *string  `json:"filter,omitempty"`
	Scope      *string  `json:"scope,omitempty"`
}

// ValidateLDAPConf checks that content is a well-formed LDAP Firewall
// config.json. It is a structural pre-check performed before the file is
// written; on Windows the manager's own "/validate" is run as a second gate
// (see Controller.ApplyConfig).
func ValidateLDAPConf(content []byte) error {
	dec := json.NewDecoder(bytesReader(content))
	dec.DisallowUnknownFields() // catch typos like "atributes"
	var cfg struct {
		Rules []json.RawMessage `json:"rules"`
		Debug *string           `json:"debug,omitempty"`
		// tolerate manager-managed keys so a round-tripped file still validates
		Offsets json.RawMessage `json:"offsets,omitempty"`
		LogPath *string         `json:"logPath,omitempty"`
	}
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("config.json is not valid JSON: %w", err)
	}
	if cfg.Rules == nil {
		return fmt.Errorf("config.json has no \"rules\" array")
	}
	if cfg.Debug != nil && *cfg.Debug != "on" && *cfg.Debug != "off" {
		return fmt.Errorf("debug %q must be on or off", *cfg.Debug)
	}
	for i, raw := range cfg.Rules {
		if err := validateLDAPRule(i, raw); err != nil {
			return err
		}
	}
	return nil
}

func validateLDAPRule(idx int, raw json.RawMessage) error {
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	var r ldapRule
	if err := dec.Decode(&r); err != nil {
		return fmt.Errorf("rule %d: %w", idx, err)
	}
	for _, op := range r.Operations {
		if !knownLDAPOperations[lower(op)] {
			return fmt.Errorf("rule %d: unknown operation %q", idx, op)
		}
	}
	if r.Action != nil && *r.Action != "allow" && *r.Action != "block" {
		return fmt.Errorf("rule %d: action %q must be allow or block", idx, *r.Action)
	}
	if r.Audit != nil && *r.Audit != "on" && *r.Audit != "off" {
		return fmt.Errorf("rule %d: audit %q must be on or off", idx, *r.Audit)
	}
	if r.Scope != nil && !knownLDAPScopes[lower(*r.Scope)] {
		return fmt.Errorf("rule %d: scope %q must be base, one level or subtree", idx, *r.Scope)
	}
	return nil
}
