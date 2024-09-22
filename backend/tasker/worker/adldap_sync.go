package worker

import (
	"ada/backend/cache"
	"ada/backend/model"
	"ada/infra/base"
	"ada/infra/ldap"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	ldap3 "github.com/go-ldap/ldap/v3"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ADLdapSyncTask 进行域内铭感条目同步
func (w *Worker) ADLdapSyncTask() error {
	ctx := context.Background()
	var ldapSearch *ldap.LDAPSearch

	// 遍历查找所有的domain redis key
	domainKeys, err := w.env.RedisCli.Keys(ctx, "ada:server:ldap:*").Result()
	if err != nil {
		logger.Errorf("redis get err:%v", err)
		return err
	}

	for _, domainKey := range domainKeys {
		parts := strings.SplitN(domainKey, ":ldap:", 2)
		if len(parts) != 2 {
			logger.Warnf("invalid domain key:%s, will ignore!", domainKey)
			continue
		}

		rdx := cache.NewRdxCli(w.env.RedisCli)

		domainName := strings.ToLower(parts[1])
		account, err := rdx.GetLDAPAccount(domainName)
		if err != nil {
			logger.Errorf("redis get ldap account err:%v, domain:%s", err, domainName)
			continue
		}

		logger.Debugf("ldap params:ldapAddr:%v\n", account)
		ldapSearch, err = ldap.NewSearch(account.Server, account.User, account.Password, account.DNS, "")
		if err != nil {
			logger.Errorf("ldap new search err:%v", err)
			continue
		}
		// 同步AD内敏感用户
		if err = w.syncSensitiveUser(ctx, ldapSearch, domainName); err != nil {
			logger.Errorf("sync sensitive user err:%v", err)
			continue
		}

		// //同步AD内敏感组
		if err = w.syncSensitiveGroup(ctx, ldapSearch, domainName); err != nil {
			logger.Errorf("sync sensitive group err:%v", err)
			continue
		}

		//同步AD内敏感计算机
		if err = w.syncSensitiveComputer(ctx, ldapSearch, domainName); err != nil {
			logger.Errorf("sync sensitive computer err:%v", err)
			continue
		}

		//同步AD内所有Users
		if err = w.syncAllUser(ldapSearch, domainName); err != nil {
			logger.Errorf("sync all user err:%v", err)
			continue
		}

		ldapSearch.Close()
	}
	return nil
}

func (w *Worker) syncSensitiveUser(ctx context.Context, ls *ldap.LDAPSearch, domainName string) error {
	logger.Debugf("start sync sensitive user, domain:%s", domainName)

	filter := "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
	result, err := ls.BasicSearch(filter, "name,sAMAccountName,objectSid")
	if err != nil {
		return err
	}

	if len(result.Entries) <= 0 {
		return nil
	}

	for _, entry := range result.Entries {
		sAMAccountName := entry.GetAttributeValues("sAMAccountName")
		objectSid := entry.GetAttributeValues("objectSid")
		if len(sAMAccountName) == 0 || len(objectSid) == 0 {
			logger.Warnf("Missing attributes for user '%s', skipping.", sAMAccountName[0])
			continue
		}

		// ignore internal user: krbtgt
		if sAMAccountName[0] == "krbtgt" {
			continue
		}

		b64sid := base64.StdEncoding.EncodeToString([]byte(objectSid[0]))
		bSid, _ := base64.StdEncoding.DecodeString(b64sid)
		sid := ldap.SIDDecode(bSid).String()

		err := w.addOrUpdateEntry(ctx, domainName, "user", sAMAccountName[0], sid)
		if err != nil {
			logger.Warnf("update sensitive entry err:%v, will ignore!", err)
			continue
		}
	}

	// 删除不存在的旧user
	// TODO:

	return nil
}

func (w *Worker) syncSensitiveGroup(ctx context.Context, ls *ldap.LDAPSearch, domainName string) error {
	logger.Debugf("start sync sensitive groups, domain:%s", domainName)

	// List of Sensitive Groups
	sensitiveGroups := []string{
		"Domain Admins",
		"Enterprise Admins",
		"Schema Admins",
		"Domain Controllers",
		"Account Operators",
		"Server Operators",
		"Enterprise Read-only Domain Controllers",
		"Key Admins",
		"Enterprise Key Admins",
		"DnsAdmins",
		"Organization Management",
		"Terminal Server License Servers",
		"Backup Operators",
		"Print Operators",
		"Administrators",
		"Remote Desktop Users",
		"Cert Publishers",
	}

	attributes := "name,sAMAccountName,objectSid"

	for _, groupName := range sensitiveGroups {
		filter := fmt.Sprintf("(&(objectClass=group)(CN=%s))", groupName)
		result, err := ls.BasicSearch(filter, attributes)
		if err != nil {
			logger.Errorf("LDAP search error for group '%s' err: %v", groupName, err)
			continue
		}

		if len(result.Entries) <= 0 {
			logger.Infof("No '%s' group found.", groupName)
			continue
		}

		for _, entry := range result.Entries {
			sAMAccountName := entry.GetAttributeValues("sAMAccountName")
			objectSid := entry.GetAttributeValues("objectSid")
			if len(sAMAccountName) == 0 || len(objectSid) == 0 {
				logger.Warnf("Missing attributes for group '%s', skipping.", groupName)
				continue
			}

			b64sid := base64.StdEncoding.EncodeToString([]byte(objectSid[0]))
			bSid, err := base64.StdEncoding.DecodeString(b64sid)
			if err != nil {
				logger.Warnf("Failed to decode SID for group '%s': %v", groupName, err)
				continue
			}

			sid := ldap.SIDDecode(bSid).String()

			err = w.addOrUpdateEntry(ctx, domainName, "group", sAMAccountName[0], sid)
			if err != nil {
				logger.Warnf("Update sensitive entry for group '%s' failed: %v, will ignore!", groupName, err)
				continue
			}
		}
	}

	// TODO: Handle removal of members no longer in the groups

	return nil
}

func (w *Worker) syncSensitiveComputer(ctx context.Context, ls *ldap.LDAPSearch, domainName string) error {
	logger.Debugf("start sync sensitive computer, domain:%s", domainName)

	filter := "(|(primarygroupid=516)(primarygroupid=521)(primarygroupid=512))"
	result, err := ls.BasicSearch(filter, "sAMAccountName,objectSid")
	if err != nil {
		return err
	}

	if len(result.Entries) <= 0 {
		return nil
	}

	for _, entry := range result.Entries {
		sAMAccountName := entry.GetAttributeValues("sAMAccountName")
		objectSid := entry.GetAttributeValues("objectSid")
		if len(sAMAccountName) == 0 || len(objectSid) == 0 {
			logger.Warnf("Missing attributes for computer, skipping.")
			continue
		}

		b64sid := base64.StdEncoding.EncodeToString([]byte(objectSid[0]))
		bSid, err := base64.StdEncoding.DecodeString(b64sid)
		if err != nil {
			logger.Warnf("Failed to decode SID for computer '%s': %v", sAMAccountName[0], err)
			continue
		}

		sid := ldap.SIDDecode(bSid).String()

		err = w.addOrUpdateEntry(ctx, domainName, "computer", sAMAccountName[0], sid)
		if err != nil {
			logger.Warnf("Update sensitive entry for computer '%s' failed: %v, will ignore!", sAMAccountName[0], err)
			continue
		}
	}

	// 删除不存在的旧computer
	// TODO:

	return nil
}

func (w *Worker) syncAllUser(ls *ldap.LDAPSearch, domainName string) error {
	filter := "(&(objectCategory=person)(objectClass=user))"
	attributeList := "name,sAMAccountName,dn,objectSid,lastLogon,pwdLastSet,mail,primaryGroupID,objectGUID,userAccountControl"
	sr := ldap3.NewSearchRequest(
		ls.Dn,
		ldap3.ScopeWholeSubtree,
		ldap3.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		strings.Split(attributeList, ","),
		nil,
	)

	result, err := ls.Conn.SearchWithPaging(sr, 500)
	if err != nil {
		return err
	}

	if len(result.Entries) <= 0 {
		return nil
	}

	var obj model.AssetUser
	var user model.AssetUser
	obj.Domain = domainName

	for _, entry := range result.Entries {
		obj.Dn = entry.DN
		for _, attr := range entry.Attributes {
			switch attr.Name {
			case "name":
				obj.Name = attr.Values[0]
			case "lastLogon":
				obj.LastLogon = base.Atoll(attr.Values[0])
			case "pwdLastSet":
				obj.PwdLastSet = base.Atoll(attr.Values[0])
			case "primaryGroupID":
				obj.PrimaryGroupID = base.Atoll(attr.Values[0])
			case "objectGUID":
				obj.ObjectGUID = fmt.Sprintf("%x", attr.Values[0])
			case "mail":
				obj.Email = attr.Values[0]
			case "sAMAccountName":
				obj.SAMAccountName = attr.Values[0]
			case "objectSid":
				b64sid := base64.StdEncoding.EncodeToString([]byte(attr.Values[0]))
				bsid, _ := base64.StdEncoding.DecodeString(b64sid)
				sid := ldap.SIDDecode(bsid)
				obj.ObjectSid = sid.String()
			case "userAccountControl":
				obj.UserAccountControl = base.Atoll(attr.Values[0])
			}
		}

		// update or add user
		_, exist := w.env.MongoCli.FindOne(obj.CollectName(), bson.M{"sAMAccountName": obj.SAMAccountName, "domain": obj.Domain}, &user)
		if exist {
			update := bson.M{
				"syncTm": time.Now().Unix(),
			}
			err = w.env.MongoCli.UpdateById(obj.CollectName(), user.ID, &update)
		} else {
			obj.ID = primitive.NewObjectID()
			obj.SyncTm = time.Now().Unix()
			err = w.env.MongoCli.Insert(obj.CollectName(), &obj)
		}
		if err != nil {
			logger.Warnf("store asset user err:%v", err)
			continue
		}
	}

	// 删除不存在的旧user
	var userList []model.AssetUser
	query := bson.D{}
	query = append(query, bson.E{Key: "domain", Value: obj.Domain})
	query = append(query, bson.E{Key: "syncTm", Value: bson.M{"$lte": time.Now().Add(-time.Minute * 10)}})
	err = w.env.MongoCli.FindAll(obj.CollectName(), query, &userList)
	if err != nil {
		logger.Errorf("find all user err:%v", err)
		return err
	}
	for _, user := range userList {
		update := bson.M{
			"isDelete": true,
			"syncTm":   time.Now().Unix(),
		}
		err = w.env.MongoCli.UpdateById(user.CollectName(), user.ID, &update)
		if err != nil {
			logger.Warnf("updat asset user err:%v", err)
			continue
		}
	}

	return nil
}

func (w *Worker) addOrUpdateEntry(ctx context.Context, domainName, entryType, name, sid string) error {
	if name == "" || sid == "" {
		return fmt.Errorf("empty sensitive entry(type:%s)", entryType)
	}

	key := cache.SensitiveEntryKey(domainName, entryType)

	var se model.SensitiveEntry
	_, exist := w.env.MongoCli.FindOne(se.CollectName(), bson.M{"domain": domainName, "type": entryType, "content.name": name}, &se)
	if exist {
		// Update the UpdateTm
		update := bson.M{
			"update_tm": time.Now(),
			"content": bson.M{
				"sid":  sid,
				"name": name,
			},
		}
		err := w.env.MongoCli.UpdateById(se.CollectName(), se.ID, &update)
		if err != nil {
			logger.Warnf("failed to update sensitive entry: %v", err)
			return fmt.Errorf("failed to update sensitive entry: %v", err)
		}

		err = w.env.RedisCli.SAdd(ctx, key, []string{name}).Err()
		if err != nil {
			logger.Warnf("redis cli save domain entry cache err:%v", err)
			return err
		}
		return nil
	}

	se.Domain = domainName
	se.Type = entryType
	se.Content = map[string]string{"sid:": sid, "name": name}
	se.Origin = 0
	se.CreateTm = time.Now()
	se.UpdateTm = time.Now()
	err := w.env.MongoCli.Insert(se.CollectName(), &se)
	if err != nil {
		return err
	}

	err = w.env.RedisCli.SAdd(ctx, key, []string{name}).Err()
	if err != nil {
		logger.Warnf("redis cli save domain entry cache err:%v", err)
		return err
	}

	return nil
}
