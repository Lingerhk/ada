package cache

import (
	"fmt"
	"github.com/redis/go-redis/v9"
	"strings"
)

type RdxCli struct {
	Cli *redis.Client
}

func NewRdxCli(RedisCli *redis.Client) *RdxCli {
	return &RdxCli{Cli: RedisCli}
}

// hash类型：
// status->str (init|run|...)
// hostname->str
func SensorIDKey(ID string) string {
	return fmt.Sprintf("ada:sensor:id:%s", ID)
}

func LDAPAccountKey(domain string) string {
	return fmt.Sprintf("ada:server:ldap:%s", strings.ToLower(domain))
}

func DomainListKey() string {
	return fmt.Sprintf("ada:server:domain_list")
}

// ip与dc的对应关系
// hash类型: key: ..domain.., field: ip, value: dc_hostname+domain
func DomainIPRelateDCKey(domain string) string {
	return fmt.Sprintf("ada:server:%s:ip_relate_dc", strings.ToLower(domain))
}

// ip与dc的对应关系
// key类型: key: ip, value: dc_hostname+domain(fqdn)
func DomainIPRelateDCNameKey(ip string) string {
	return fmt.Sprintf("ada:engine:dc_ip:%s", ip)
}

// 敏感条目
// set类型
func SensitiveEntryKey(domain, entryType string) string {
	var key string
	keyFormat := "ada:engine:%s:%s"
	switch entryType {
	case "user":
		key = fmt.Sprintf(keyFormat, strings.ToLower(domain), "sensitive_users")
	case "group":
		key = fmt.Sprintf(keyFormat, strings.ToLower(domain), "sensitive_groups")
	case "computer":
		key = fmt.Sprintf(keyFormat, strings.ToLower(domain), "sensitive_computers")
	case "honeyuser":
		key = fmt.Sprintf(keyFormat, strings.ToLower(domain), "honeypot_accounts")
	}
	return key
}
