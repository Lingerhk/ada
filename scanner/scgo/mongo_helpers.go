package scgo

import (
	"ada/scanner/config"
	"fmt"
	"net/url"
	"strings"

	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"
)

type MongoConnInfo struct {
	Host       string
	Port       int
	Username   string
	Password   string
	Database   string
	AuthSource string
}

func ParseMongoURI(uri string) (*MongoConnInfo, error) {
	cs, err := connstring.Parse(uri)
	if err != nil {
		return nil, err
	}
	info := &MongoConnInfo{}
	if len(cs.Hosts) > 0 {
		// cs.Hosts contains host[:port]
		hp := cs.Hosts[0]
		h, p, found := strings.Cut(hp, ":")
		if found {
			info.Host = h
			_, _ = fmt.Sscanf(p, "%d", &info.Port)
		} else {
			info.Host = hp
		}
	}
	// Better parse using net/url for credentials/db/authSource.
	u, err := url.Parse(uri)
	if err == nil {
		hostport := u.Host
		// url.Parse for mongodb:// already strips userinfo into u.User, so u.Host is host:port.
		h, p, found := strings.Cut(hostport, ":")
		if found {
			info.Host = h
			_, _ = fmt.Sscanf(p, "%d", &info.Port)
		} else if hostport != "" {
			info.Host = hostport
		}

		if u.User != nil {
			info.Username = u.User.Username()
			pw, _ := u.User.Password()
			info.Password = pw
		}
		if u.Path != "" {
			info.Database = strings.TrimPrefix(u.Path, "/")
		}
		q := u.Query()
		info.AuthSource = q.Get("authSource")
		if info.AuthSource == "" {
			info.AuthSource = info.Database
		}
	}

	if info.Host == "" {
		// fallback to connstring host
		if len(cs.Hosts) > 0 {
			// could include port
			hp := cs.Hosts[0]
			if strings.Contains(hp, ":") {
				parts := strings.Split(hp, ":")
				info.Host = parts[0]
			} else {
				info.Host = hp
			}
		}
	}
	if info.Port == 0 {
		info.Port = 27017
	}
	if info.Database == "" {
		info.Database = cs.Database
	}
	if info.AuthSource == "" {
		info.AuthSource = cs.AuthSource
		if info.AuthSource == "" {
			info.AuthSource = info.Database
		}
	}
	if info.Username == "" {
		info.Username = cs.Username
	}
	if info.Password == "" {
		info.Password = cs.Password
	}
	return info, nil
}

func MongoEnvFromConfig(cfg *config.Config) (map[string]any, error) {
	ci, err := ParseMongoURI(cfg.Mongodb.URI)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"host":     fmt.Sprintf("%s:%d", ci.Host, ci.Port),
		"user":     ci.Username,
		"password": ci.Password,
		// Python uses authSource as db_name
		"db_name": ci.AuthSource,
	}, nil
}
