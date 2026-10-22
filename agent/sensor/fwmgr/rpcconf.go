package fwmgr

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// rpcProtocolSeqs are the RPC protocol-sequence names accepted in a "prot:"
// token (the subset the upstream filter/firewall code recognises).
var rpcProtocolSeqs = map[string]bool{
	"ncacn_ip_tcp": true,
	"ncacn_np":     true,
	"ncacn_http":   true,
	"ncalrpc":      true,
	"remote":       true,
}

// rpcConfKeys are the recognised key: prefixes inside an RpcFw.conf rule line.
var rpcConfKeys = map[string]bool{
	"uuid": true, "opnum": true, "addr": true, "prot": true,
	"action": true, "audit": true, "verbose": true, "sid": true,
}

// ValidateRPCConf checks that content is a well-formed RpcFw.conf so a broken
// configuration is never pushed to the RPC Firewall. Each non-blank line must
// begin with the scope "fw:" (RPC Firewall) or "flt:" (RPC Filters) and consist
// of space-separated key:value tokens drawn from rpcConfKeys.
func ValidateRPCConf(content []byte) error {
	sc := bufio.NewScanner(bytes.NewReader(content))
	rules := 0
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		scope, rest, ok := cutScope(text)
		if !ok {
			return fmt.Errorf("line %d: must start with %q or %q: %q", line, "fw:", "flt:", text)
		}
		if err := validateRPCTokens(rest); err != nil {
			return fmt.Errorf("line %d (%s): %w", line, scope, err)
		}
		rules++
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if rules == 0 {
		return fmt.Errorf("no fw:/flt: rule lines")
	}
	return nil
}

func cutScope(line string) (scope, rest string, ok bool) {
	switch {
	case strings.HasPrefix(line, "fw:"):
		return "fw", strings.TrimPrefix(line, "fw:"), true
	case strings.HasPrefix(line, "flt:"):
		return "flt", strings.TrimPrefix(line, "flt:"), true
	default:
		return "", "", false
	}
}

func validateRPCTokens(rest string) error {
	seen := false
	for _, tok := range strings.Fields(rest) {
		key, val, ok := strings.Cut(tok, ":")
		if !ok {
			return fmt.Errorf("token %q is not key:value", tok)
		}
		key = strings.ToLower(key)
		if !rpcConfKeys[key] {
			return fmt.Errorf("unknown key %q", key)
		}
		if err := validateRPCValue(key, val); err != nil {
			return err
		}
		seen = true
	}
	if !seen {
		return fmt.Errorf("rule line has no tokens")
	}
	return nil
}

func validateRPCValue(key, val string) error {
	switch key {
	case "opnum":
		if _, err := strconv.Atoi(val); err != nil {
			return fmt.Errorf("opnum %q is not an integer", val)
		}
	case "addr":
		if _, err := netip.ParseAddr(val); err != nil {
			if _, err := netip.ParsePrefix(val); err != nil {
				return fmt.Errorf("addr %q is not an IP or CIDR", val)
			}
		}
	case "prot":
		if !rpcProtocolSeqs[strings.ToLower(val)] {
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
	case "uuid", "sid":
		if val == "" {
			return fmt.Errorf("%s has no value", key)
		}
	}
	return nil
}
