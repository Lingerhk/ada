// author: adaegis
// time: 2020-09-06
// desc:

package ldap

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	ldap3 "github.com/go-ldap/ldap/v3"
)

var ErrEmptyResult = fmt.Errorf("empty result")

const IPReg = `^((0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.){3}(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])$`

// 返回dialURL对应解析的可用IP地址
func GetEnableIP(dialURL, dns string) (string, error) {
	var ips []string
	var err error

	if dns != "" {
		// 如果dns指定，且DialURL为域名格式，则指定dns进行ldap查询
		// DialURL格式: ldap[s]://host:port
		parts := strings.SplitN(dialURL, "://", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid ldap url format")
		}
		addr := strings.SplitN(parts[1], ":", 2)
		host := addr[0] // 校验DialURL为ip格式，如果DialURL中存在port，取host部分

		// 如果DialURL格式（ldap[s]://host:port）中的host为非IP格式（即域名格式），则进行dns解析
		r, _ := regexp.Compile(IPReg)
		if r.MatchString(host) {
			// IP格式，直接返回
			return host, nil
		}

		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, "udp", fmt.Sprintf("%s:53", dns))
			},
		}

		ips, err = resolver.LookupHost(context.Background(), host)
		if err != nil {
			return "", err
		}
	} else {
		ips, err = net.LookupHost(dialURL)
		if err != nil {
			return "", err
		}
	}

	// 判断可用IP即返回
	for _, ip := range ips {
		_, err := net.DialTimeout("tcp", ip+":389", 2*time.Second)
		if err != nil {
			continue
		}
		return ip, nil
	}

	return "", fmt.Errorf("all ips unable to connect")
}

// 创建ldap查询连接，dns为可选参数，DialURL格式为: ldap[s]://host:port(host可为ip或域名)
func GetConn(DialURL, user, password, dns string) (*ldap3.Conn, error) {
	var c *ldap3.Conn
	var err error
	if dns != "" {
		// 如果dns指定，且DialURL为域名格式，则指定dns进行ldap查询
		// DialURL格式: ldap[s]://host:port
		parts := strings.SplitN(DialURL, "://", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid ldap url format")
		}
		addr := strings.SplitN(parts[1], ":", 2)
		host := addr[0] // 校验DialURL为ip格式，如果DialURL中存在port，取host部分

		// 如果DialURL格式（ldap[s]://host:port）中的host为非IP格式（即域名格式），则进行dns解析
		r, _ := regexp.Compile(IPReg)
		if !r.MatchString(host) {
			ip, err := GetEnableIP(DialURL, dns)
			if err != nil {
				return nil, err
			}

			dialAddr := fmt.Sprintf("%s://%s", parts[0], ip)
			c, err = ldap3.DialURL(dialAddr)
		}
	} else {
		c, err = ldap3.DialURL(DialURL)
	}
	if err != nil {
		return nil, err
	}

	// ldap3's error define from: github.com/go-ldap/ldap/v3/error.go
	// https://ldap.com/ldap-result-code-reference/
	// if Authenticate failed(such invalid password), the error is LDAPResultInvalidCredentials(result code is 49)
	err = c.Bind(user, password)
	if err != nil {
		return nil, err
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

func SearchWithPage(DialURL, dns, dn, user, password, filter string, attributes []string, pageSize uint32) (*ldap3.SearchResult, error) {
	c, err := GetConn(DialURL, user, password, dns)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	sr := ldap3.NewSearchRequest(
		dn,
		ldap3.ScopeSingleLevel, // ScopeWholeSubtree|ScopeSingleLevel|xx
		ldap3.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	res, err := c.SearchWithPaging(sr, pageSize)
	if err != nil {
		return nil, err
	}

	return res, nil
}
