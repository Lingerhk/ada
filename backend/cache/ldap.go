package cache

import (
	base_common "ada/backend/common"
	"encoding/base64"
	"fmt"

	"golang.org/x/net/context"

	"ada/infra/crypto"

	jsoniter "github.com/json-iterator/go"
	logger "github.com/sirupsen/logrus"
)

var ErrEmptyResult = fmt.Errorf("empty result")

type LDAPAccount struct {
	Server   string `json:"server"`
	User     string `json:"user"`
	Password string `json:"password"`
	Dn       string `json:"dn"`
	DNS      string `json:"dns"`
}

func (r *RdxCli) GetLDAPAccount(domain string) (*LDAPAccount, error) {
	accountInfo, err := r.Cli.Get(context.Background(), LDAPAccountKey(domain)).Result()
	if err != nil {
		logger.Errorf("redis get ldap account err:%v, domain:%s", err, domain)
		return nil, err
	}
	if accountInfo == "" {
		logger.Errorf("redis get ldap account err:%v, domain:%s", err, domain)
		return nil, ErrEmptyResult
	}

	var account LDAPAccount
	err = jsoniter.UnmarshalFromString(accountInfo, &account)
	if err != nil {
		logger.Errorf("json unmarshal err:%v, domain:%s", err, domain)
		return nil, err
	}

	if account.Password != "" {
		// decrypt account password using AES-256-GCM
		aesGCM, err := crypto.NewAesGCM([]byte(base_common.RDX_CRYPT_SECRET))
		if err != nil {
			logger.Errorf("create AES-GCM failed:%v, domain:%s", err, domain)
			return nil, err
		}

		encByte, err := base64.StdEncoding.DecodeString(account.Password)
		if err != nil {
			logger.Errorf("base64 decode err:%v, domain:%s", err, domain)
			return nil, err
		}

		pass, err := aesGCM.Decrypt(encByte)
		if err != nil {
			logger.Errorf("aes-gcm decrypt failed:%v, domain:%s", err, domain)
			return nil, err
		}
		account.Password = string(pass)
	}

	return &account, nil
}
