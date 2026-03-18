package scgo

import (
	"ada/scanner/common"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type DCInfo struct {
	HostName   string
	Platform   string
	IPList     []string
	Status     string
	ErrMsg     string
	LastOnline any
}

func (s *Service) getDomainByName(name string) (bson.M, error) {
	var dm bson.M
	err, exist := s.MongoCli.FindOne(s.mongoContext(), "tb_domain", bson.M{"name": name}, &dm)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, fmt.Errorf("domain not found: %s", name)
	}

	// decrypt ldap_conf.password
	ldapConfAny := dm["ldap_conf"]
	ldapConf, _ := mapFromAny(ldapConfAny)
	if ldapConf != nil {
		if pwEnc, ok := ldapConf["password"].(string); ok && pwEnc != "" {
			if pw, err := DecryptDomainPasswordGCM(common.DomainPwdKeyGCM, pwEnc); err == nil {
				ldapConf["password"] = pw
			}
		}

		// normalize user format: "DOMAIN\\user" -> "user@domain"
		if u, ok := ldapConf["user"].(string); ok {
			if strings.Contains(u, "\\") {
				parts := strings.Split(u, "\\")
				if len(parts) >= 2 {
					ldapConf["user"] = parts[len(parts)-1] + "@" + name
				}
			}
		}
		dm["ldap_conf"] = ldapConf
	}

	return dm, nil
}

func extractDCList(dm bson.M) []map[string]any {
	if arr, ok := asSliceAny(dm["dc_list"]); ok {
		out := make([]map[string]any, 0, len(arr))
		for _, it := range arr {
			if m, ok := mapFromAny(it); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

func firstIP(dc map[string]any) string {
	ips := dc["ip_list"]
	if vv, ok := ips.([]string); ok {
		if len(vv) > 0 {
			return vv[0]
		}
		return ""
	}
	if arr, ok := asSliceAny(ips); ok {
		if len(arr) > 0 {
			if s, ok := arr[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

func getOnlineDC(dm bson.M) (map[string]any, bool) {
	for _, dc := range extractDCList(dm) {
		if st, _ := dc["status"].(string); st == "run" {
			return dc, true
		}
	}
	return nil, false
}

func getOnlineDCWeakPwd(dm bson.M) (map[string]any, bool) {
	for _, dc := range extractDCList(dm) {
		if st, _ := dc["status"].(string); st != "run" {
			continue
		}
		ip := firstIP(dc)
		if ip == "" {
			continue
		}
		if err := DialTCP(fmt.Sprintf("%s:445", ip), 2*time.Second); err == nil {
			return dc, true
		}
	}
	return nil, false
}

func getTargetDC(dm bson.M, hostname string) (map[string]any, bool) {
	for _, dc := range extractDCList(dm) {
		h, _ := dc["hostname"].(string)
		if h == hostname {
			return dc, true
		}
	}
	return nil, false
}
