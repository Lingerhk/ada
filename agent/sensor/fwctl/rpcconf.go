package fwctl

import (
	"bufio"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ValidateRPCConf checks that content is a well-formed RpcFw.conf before it is
// written to disk and handed to the RPC Firewall. The goal is to reject a
// configuration that the firewall would reject or that would silently change
// behaviour, so that a bad push never leaves a domain controller unprotected.
//
// Grammar (from the upstream rpcFirewall config parser): the file is a list of
// lines; blank lines are ignored; every other line must begin with "fw:" (RPC
// Firewall) or "flt:" (RPC Filters) and is a space-separated list of
// key:value tokens. Recognised keys: uuid, opnum, addr, prot, action, audit,
// verbose, sid.
func ValidateRPCConf(content []byte) error {
	lines := bufio.NewScanner(strings.NewReader(string(content)))
	meaningful := 0
	n := 0
	for lines.Scan() {
		n++
		raw := strings.TrimSpace(lines.Text())
		if raw == "" {
			continue
		}
		if !strings.HasPrefix(raw, "fw:") && !strings.HasPrefix(raw, "flt:") {
			return fmt.Errorf("line %d: must start with 'fw:' or 'flt:': %q", n, raw)
		}
		if err := validateRPCConfLine(raw); err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		meaningful++
	}
	if err := lines.Err(); err != nil {
		return err
	}
	if meaningful == 0 {
		return fmt.Errorf("configuration has no fw:/flt: rule lines")
	}
	return nil
}

func validateRPCConfLine(line string) error {
	fields := strings.Fields(line)
	// fields[0] is the fw:/flt: prefix, optionally carrying the first token
	// (e.g. "fw:action:allow"); normalise by stripping the leading scope.
	for _, tok := range fields {
		tok = strings.TrimPrefix(tok, "fw:")
		tok = strings.TrimPrefix(tok, "flt:")
		if tok == "" {
			continue
		}
		key, val, ok := strings.Cut(tok, ":")
		if !ok {
			return fmt.Errorf("token %q is not key:value", tok)
		}
		if err := validateRPCConfToken(strings.ToLower(key), val); err != nil {
			return err
		}
	}
	return nil
}

var rpcProtocols = map[string]bool{
	"ncacn_ip_tcp": true,
	"ncacn_np":     true,
	"ncacn_http":   true,
	"ncalrpc":      true,
	"remote":       true,
}

func validateRPCConfToken(key, val string) error {
	switch key {
	case "uuid":
		if val == "" {
			return fmt.Errorf("uuid is empty")
		}
	case "opnum":
		if _, err := strconv.Atoi(val); err != nil {
			return fmt.Errorf("opnum %q is not an integer", val)
		}
	case "addr":
		if _, err := netip.ParseAddr(val); err != nil {
			if _, err2 := netip.ParsePrefix(val); err2 != nil {
				return fmt.Errorf("addr %q is not an IP or CIDR", val)
			}
		}
	case "prot":
		if !rpcProtocols[strings.ToLower(val)] {
			return fmt.Errorf("prot %q is not a known protocol sequence", val)
		}
	case "action":
		if val != "allow" && val != "block" {
			return fmt.Errorf("action %q must be allow or block", val)
		}
	case "audit", "verbose":
		if val != "true" && val != "false" {
			return fmt.Errorf("%s %q must be true or false", key, val)
		}
	case "sid":
		if val == "" {
			return fmt.Errorf("sid is empty")
		}
	default:
		return fmt.Errorf("unknown key %q", key)
	}
	return nil
}
