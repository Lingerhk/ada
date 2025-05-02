// author: s0nnet
// time: 2021-01-05
// desc:

package ldap

import (
	"fmt"
	"net/url"
	"strings"

	ldap3 "github.com/go-ldap/ldap/v3"
)

type LDAPSearch struct {
	Conn   *ldap3.Conn
	Dn     string
	Domain string
}

func NewSearch(ldapAddr, user, password, dns, dnPrefix string) (*LDAPSearch, error) {
	ldap, err := url.Parse(ldapAddr)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(ldap.Host, ".")
	domain := strings.Join(parts[1:], ".")
	dn := "DC=" + strings.Join(parts[1:], ",DC=")

	if dnPrefix != "" {
		dn = fmt.Sprintf("%s,%s", dnPrefix, dn)
	}

	conn, err := GetConn(ldapAddr, user, password, dns)
	if err != nil {
		return nil, err
	}

	return &LDAPSearch{
		Conn:   conn,
		Dn:     dn,
		Domain: domain,
	}, nil
}

func (r *LDAPSearch) Close() {
	r.Conn.Close()
}

// Basic search
func (r *LDAPSearch) BasicSearch(filter, attributes string) (*ldap3.SearchResult, error) {
	var attr []string
	if attributes == "" {
		attr = []string{"CN"}
	} else {
		attr = strings.Split(attributes, ",")
	}

	return Search(r.Conn, r.Dn, filter, attr)
}

// 通过SID搜索
func (r *LDAPSearch) LdapSearchBySid(sid, attributes string) (*ldap3.Entry, error) {
	filter := fmt.Sprintf("(ObjectSID=%s)", sid)
	result, err := r.BasicSearch(filter, attributes)
	if err != nil {
		return nil, err
	}

	if len(result.Entries) <= 0 {
		return nil, ErrEmptyResult
	}

	return result.Entries[0], nil
}

// 通过用户名搜索
func (r *LDAPSearch) LdapSearchByName(user, attributes string) (*ldap3.Entry, error) {
	filter := fmt.Sprintf("(sAMAccountName=%s)", user)
	result, err := r.BasicSearch(filter, attributes)
	if err != nil {
		return nil, err
	}
	if len(result.Entries) <= 0 {
		return nil, ErrEmptyResult
	}
	return result.Entries[0], nil
}

// 通过CN搜索
func (r *LDAPSearch) LdapSearchByCN(cn, attributes string) (*ldap3.Entry, error) {
	filter := fmt.Sprintf("(CN=%s)", cn)
	result, err := r.BasicSearch(filter, attributes)
	if err != nil {
		return nil, err
	}

	if len(result.Entries) <= 0 {
		return nil, ErrEmptyResult
	}
	return result.Entries[0], nil
}

// 搜索 dc hostname list
func (r *LDAPSearch) LdapSearchDomainController() ([]*ldap3.Entry, error) {
	// 此处查询的filter进行了优化
	//filter := fmt.Sprint("(&(objectCategory=computer)(objectClass=computer))")
	filter := "(|(primarygroupid=516)(primarygroupid=521))"
	result, err := r.BasicSearch(filter, "cn,dnsHostName,objectSid,operatingSystem,operatingSystemVersion")
	if err != nil {
		return nil, err
	}

	if len(result.Entries) <= 0 {
		return nil, ErrEmptyResult
	}

	return result.Entries, nil
}
