package ldap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	ldap3 "github.com/go-ldap/ldap/v3"
)

var (
	ErrEmptyResult = errors.New("empty result")
)

// resolveHost returns the available IP address resolved from the host
func resolveHost(host, portStr, dns string) (string, error) {
	// host is a domain name, resolve to IPs
	var ips []string

	// Use custom DNS resolver
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			// Ensure custom DNS server address includes port 53
			dnsAddr := dns
			if !strings.Contains(dnsAddr, ":") {
				dnsAddr = fmt.Sprintf("%s:53", dnsAddr)
			}
			return d.DialContext(ctx, "udp", dnsAddr)
		},
	}
	ips, err := resolver.LookupHost(context.Background(), host)
	if err != nil {
		return "", fmt.Errorf("dns lookup failed for %s using %s: %v", host, dns, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no ips found for host %s", host)
	}

	// Check reachability of resolved IPs
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, portStr)
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err == nil {
			conn.Close()
			return ip, nil // Return the first reachable IP
		}
	}

	return "", fmt.Errorf("all resolved ips for %s are unable to connect", host)
}

// GetConn creates an LDAP query connection, dns is optional parameter, DialURL format: ldap[s]://host:port (host can be IP or domain name)
func GetConn(DialURL, user, password, dns string) (*ldap3.Conn, error) {
	// 1. Parse DialURL
	u, err := url.Parse(DialURL)
	if err != nil {
		return nil, fmt.Errorf("invalid ldap url format '%s': %v", DialURL, err)
	}
	scheme := u.Scheme
	host := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		switch u.Scheme {
		case "ldap":
			portStr = "389"
		case "ldaps":
			portStr = "636"
		default:
			return nil, fmt.Errorf("unsupported scheme or missing port: %s", scheme)
		}
	}

	dialHost := host // Start with the original host

	// 2. Resolve IP if custom DNS is provided and host is a domain name
	if dns != "" && net.ParseIP(host) == nil { // Use net.ParseIP to check if host is NOT an IP
		resolvedIP, err := resolveHost(host, portStr, dns) // DialURL provides context for resolveHost
		if err != nil {
			return nil, fmt.Errorf("failed to get enable ip using custom dns %s for %s: %v", dns, host, err)
		}
		dialHost = resolvedIP // Use the resolved IP for dialing
	}

	// 3. Construct final dial address
	dialAddr := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(dialHost, portStr))

	// 4. Dial LDAP server
	c, err := ldap3.DialURL(dialAddr)
	if err != nil {
		// Provide context about whether resolution was attempted
		originalURLInfo := DialURL
		if dialAddr != DialURL {
			originalURLInfo = fmt.Sprintf("%s (original: %s)", dialAddr, DialURL)
		}
		return nil, fmt.Errorf("ldap dial failed for %s: %w", originalURLInfo, err)
	}

	// 5. Bind
	// ldap3's error define from: github.com/go-ldap/ldap/v3/error.go
	// https://ldap.com/ldap-result-code-reference/
	// if Authenticate failed(such invalid password), the error is LDAPResultInvalidCredentials(result code is 49)
	err = c.Bind(user, password)
	if err != nil {
		c.Close() // Ensure connection is closed if bind fails
		return nil, fmt.Errorf("ldap bind failed for user %s on %s: %w", user, dialAddr, err)
	}

	return c, nil
}

func Search(conn *ldap3.Conn, dn, filter string, attributes []string) (*ldap3.SearchResult, error) {
	//defer conn.Close()

	sr := ldap3.NewSearchRequest(
		dn,
		ldap3.ScopeWholeSubtree,
		ldap3.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	res, err := conn.Search(sr)
	if err != nil {
		return nil, err
	}

	return res, nil
}
