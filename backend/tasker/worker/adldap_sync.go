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
	"go.mongodb.org/mongo-driver/v2/bson"
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

		// 同步AD内所有Groups
		if err = w.syncAllGroup(ldapSearch, domainName); err != nil {
			logger.Errorf("sync all group err:%v", err)
			continue
		}

		// 同步AD内所有Computers
		if err = w.syncAllComputer(ldapSearch, domainName); err != nil {
			logger.Errorf("sync all computer err:%v", err)
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

	currTm := time.Now()

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

		err := w.addOrUpdateEntry(ctx, currTm, domainName, "user", sAMAccountName[0], sid)
		if err != nil {
			logger.Warnf("update sensitive entry err:%v, will ignore!", err)
			continue
		}
	}

	// 删除不存在的旧user
	if err := w.deleteRemovedEntry(ctx, currTm, domainName, "user"); err != nil {
		logger.Warnf("delete removed entry(type: user) err:%v, will ignore!", err)
	}

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

	currTm := time.Now()

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

			err = w.addOrUpdateEntry(ctx, currTm, domainName, "group", sAMAccountName[0], sid)
			if err != nil {
				logger.Warnf("Update sensitive entry for group '%s' failed: %v, will ignore!", groupName, err)
				continue
			}
		}
	}

	// 删除旧的不存在的Group
	if err := w.deleteRemovedEntry(ctx, currTm, domainName, "group"); err != nil {
		logger.Warnf("delete removed entry(type: group) err:%v, will ignore!", err)
	}

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

	currTm := time.Now()

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

		err = w.addOrUpdateEntry(ctx, currTm, domainName, "computer", sAMAccountName[0], sid)
		if err != nil {
			logger.Warnf("Update sensitive entry for computer '%s' failed: %v, will ignore!", sAMAccountName[0], err)
			continue
		}
	}

	// 删除旧的不存在的Computer
	if err := w.deleteRemovedEntry(ctx, currTm, domainName, "computer"); err != nil {
		logger.Warnf("delete removed entry(type: computer) err:%v, will ignore!", err)
	}

	return nil
}

func (w *Worker) syncAllUser(ls *ldap.LDAPSearch, domainName string) error {
	logger.Debugf("start sync full-user, domain:%s", domainName)

	filter := "(&(objectCategory=person)(objectClass=user))"
	attributeList := "name,sAMAccountName,dn,objectSid,lastLogon,pwdLastSet,mail,primaryGroupID,objectGUID,userAccountControl,whenCreated,whenChanged"
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
			case "whenCreated":
				if ts, err := ldap.ParseGeneralizedTime(attr.Values[0]); err == nil {
					obj.WhenCreated = ts
				}
			case "whenChanged":
				if ts, err := ldap.ParseGeneralizedTime(attr.Values[0]); err == nil {
					obj.WhenChanged = ts
				}
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
			obj.ID = bson.NewObjectID()
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

// 同步AD内所有Groups
func (w *Worker) syncAllGroup(ls *ldap.LDAPSearch, domainName string) error {
	logger.Debugf("start sync full-group, domain:%s", domainName)

	filter := "(objectClass=group)"
	attributeList := "name,sAMAccountName,dn,objectSid,objectGUID,adminCount,groupType,objectCategory,nTSecurityDescriptor,whenCreated,whenChanged"
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

	var obj model.AssetGroup
	var group model.AssetGroup
	obj.Domain = domainName

	for _, entry := range result.Entries {
		obj.Dn = entry.DN
		for _, attr := range entry.Attributes {
			switch attr.Name {
			case "name":
				obj.Name = attr.Values[0]
			case "sAMAccountName":
				obj.SAMAccountName = attr.Values[0]
			case "adminCount":
				obj.AdminCount = base.Atoll(attr.Values[0])
			case "groupType":
				obj.GroupType = base.Atoll(attr.Values[0])
				// Parse groupType bitmask to get scope and category
				obj.GroupScope, obj.GroupCategory = ldap.ParseGroupType(obj.GroupType)
			case "objectGUID":
				obj.ObjectGUID = fmt.Sprintf("%x", attr.Values[0])
			case "objectCategory":
				obj.ObjectCategory = attr.Values[0]
			case "nTSecurityDescriptor":
				// nTSecurityDescriptor is binary data, encode as base64
				obj.NTSecurityDescriptor = base64.StdEncoding.EncodeToString([]byte(attr.Values[0]))
			case "objectSid":
				b64sid := base64.StdEncoding.EncodeToString([]byte(attr.Values[0]))
				bsid, _ := base64.StdEncoding.DecodeString(b64sid)
				sid := ldap.SIDDecode(bsid)
				obj.ObjectSid = sid.String()
			case "whenCreated":
				if ts, err := ldap.ParseGeneralizedTime(attr.Values[0]); err == nil {
					obj.WhenCreated = ts
				}
			case "whenChanged":
				if ts, err := ldap.ParseGeneralizedTime(attr.Values[0]); err == nil {
					obj.WhenChanged = ts
				}
			}
		}

		// update or add group
		_, exist := w.env.MongoCli.FindOne(obj.CollectName(), bson.M{"sAMAccountName": obj.SAMAccountName, "domain": obj.Domain}, &group)
		if exist {
			update := bson.M{
				"syncTm": time.Now().Unix(),
			}
			err = w.env.MongoCli.UpdateById(obj.CollectName(), group.ID, &update)
		} else {
			obj.ID = bson.NewObjectID()
			obj.SyncTm = time.Now().Unix()
			err = w.env.MongoCli.Insert(obj.CollectName(), &obj)
		}
		if err != nil {
			logger.Warnf("store asset group err:%v", err)
			continue
		}
	}

	// 删除不存在的旧group
	var groupList []model.AssetGroup
	query := bson.D{}
	query = append(query, bson.E{Key: "domain", Value: obj.Domain})
	query = append(query, bson.E{Key: "syncTm", Value: bson.M{"$lte": time.Now().Add(-time.Minute * 10)}})
	err = w.env.MongoCli.FindAll(obj.CollectName(), query, &groupList)
	if err != nil {
		logger.Errorf("find all group err:%v", err)
		return err
	}
	for _, group := range groupList {
		update := bson.M{
			"isDelete": true,
			"syncTm":   time.Now().Unix(),
		}
		err = w.env.MongoCli.UpdateById(group.CollectName(), group.ID, &update)
		if err != nil {
			logger.Warnf("update asset group err:%v", err)
			continue
		}
	}

	return nil
}

// 同步AD内所有Computers
func (w *Worker) syncAllComputer(ls *ldap.LDAPSearch, domainName string) error {
	logger.Debugf("start sync full-computer, domain:%s", domainName)

	filter := "(objectClass=computer)"
	attributeList := "name,sAMAccountName,dn,objectSid,objectGUID,operatingSystem,operatingSystemVersion,dNSHostName,servicePrincipalName,countryCode,isCriticalSystemObject,userAccountControl,whenCreated,whenChanged,primaryGroupID,lastLogonTimestamp"
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

	var obj model.AssetComputer
	var computer model.AssetComputer
	obj.Domain = domainName

	for _, entry := range result.Entries {
		obj.Dn = entry.DN
		for _, attr := range entry.Attributes {
			switch attr.Name {
			case "name":
				obj.Name = attr.Values[0]
			case "sAMAccountName":
				obj.SAMAccountName = attr.Values[0]
			case "operatingSystem":
				obj.OperatingSystem = attr.Values[0]
			case "operatingSystemVersion":
				obj.OperatingSystemVersion = attr.Values[0]
			case "dNSHostName":
				obj.DnsHostName = attr.Values[0]
			case "servicePrincipalName":
				obj.ServicePrincipalName = attr.Values
			case "countryCode":
				obj.CountryCode = base.Atoll(attr.Values[0])
			case "objectGUID":
				obj.ObjectGUID = fmt.Sprintf("%x", attr.Values[0])
			case "isCriticalSystemObject":
				obj.IsCriticalSystemObject = attr.Values[0] == "TRUE"
			case "userAccountControl":
				obj.UserAccountControl = base.Atoll(attr.Values[0])
			case "whenCreated":
				if ts, err := ldap.ParseGeneralizedTime(attr.Values[0]); err == nil {
					obj.WhenCreated = ts
				}
			case "whenChanged":
				if ts, err := ldap.ParseGeneralizedTime(attr.Values[0]); err == nil {
					obj.WhenChanged = ts
				}
			case "primaryGroupID":
				obj.PrimaryGroupID = base.Atoll(attr.Values[0])
			case "lastLogonTimestamp":
				obj.LastLogonTimestamp = base.Atoll(attr.Values[0])
			case "objectSid":
				b64sid := base64.StdEncoding.EncodeToString([]byte(attr.Values[0]))
				bsid, _ := base64.StdEncoding.DecodeString(b64sid)
				sid := ldap.SIDDecode(bsid)
				obj.ObjectSid = sid.String()
			}
		}

		// update or add computer
		_, exist := w.env.MongoCli.FindOne(obj.CollectName(), bson.M{"sAMAccountName": obj.SAMAccountName, "domain": obj.Domain}, &computer)
		if exist {
			update := bson.M{
				"syncTm": time.Now().Unix(),
			}
			err = w.env.MongoCli.UpdateById(obj.CollectName(), computer.ID, &update)
		} else {
			obj.ID = bson.NewObjectID()
			obj.SyncTm = time.Now().Unix()
			err = w.env.MongoCli.Insert(obj.CollectName(), &obj)
		}
		if err != nil {
			logger.Warnf("store asset computer err:%v", err)
			continue
		}
	}

	// 删除不存在的旧computer
	var computerList []model.AssetComputer
	query := bson.D{}
	query = append(query, bson.E{Key: "domain", Value: obj.Domain})
	query = append(query, bson.E{Key: "syncTm", Value: bson.M{"$lte": time.Now().Add(-time.Minute * 10)}})
	err = w.env.MongoCli.FindAll(obj.CollectName(), query, &computerList)
	if err != nil {
		logger.Errorf("find all computer err:%v", err)
		return err
	}
	for _, computer := range computerList {
		update := bson.M{
			"isDelete": true,
			"syncTm":   time.Now().Unix(),
		}
		err = w.env.MongoCli.UpdateById(computer.CollectName(), computer.ID, &update)
		if err != nil {
			logger.Warnf("update asset computer err:%v", err)
			continue
		}
	}

	return nil
}

func (w *Worker) addOrUpdateEntry(ctx context.Context, currTm time.Time, domainName, entryType, name, sid string) error {
	if name == "" || sid == "" {
		return fmt.Errorf("empty sensitive entry(type:%s)", entryType)
	}

	key := cache.SensitiveEntryKey(domainName, entryType)

	var se model.SensitiveEntry
	_, exist := w.env.MongoCli.FindOne(se.CollectName(), bson.M{"domain": domainName, "type": entryType, "content.name": name}, &se)
	if exist {
		// Update the UpdateTm
		update := bson.M{
			"update_tm": currTm,
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
	se.CreateTm = currTm
	se.UpdateTm = currTm
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

// 删除不存在的user/group/computer
func (w *Worker) deleteRemovedEntry(ctx context.Context, currTm time.Time, domainName, entryType string) error {
	// Find all entries that were not updated in this sync (UpdateTm < currTm)
	// and were auto-synced from LDAP (Origin = 0)
	var entryList []model.SensitiveEntry
	query := bson.M{
		"domain":    domainName,
		"type":      entryType,
		"origin":    0,                     // Only delete auto-synced entries
		"update_tm": bson.M{"$lt": currTm}, // Not updated in current sync
	}

	err := w.env.MongoCli.FindAll((&model.SensitiveEntry{}).CollectName(), query, &entryList)
	if err != nil {
		logger.Errorf("find stale sensitive entries (type: %s) err: %v", entryType, err)
		return err
	}

	if len(entryList) == 0 {
		return nil
	}

	key := cache.SensitiveEntryKey(domainName, entryType)

	// Delete each stale entry from MongoDB and Redis
	for _, entry := range entryList {
		// Delete from MongoDB
		err = w.env.MongoCli.RemoveById(entry.CollectName(), entry.ID)
		if err != nil {
			logger.Warnf("failed to delete sensitive entry (id: %s, type: %s) err: %v", entry.ID.Hex(), entryType, err)
			continue
		}

		// Remove from Redis cache
		if name, ok := entry.Content["name"]; ok && name != "" {
			err = w.env.RedisCli.SRem(ctx, key, name).Err()
			if err != nil {
				logger.Warnf("failed to remove from redis cache (name: %s, type: %s) err: %v", name, entryType, err)
			}
		}

		logger.Debugf("deleted stale sensitive entry (domain: %s, type: %s, name: %s)", domainName, entryType, entry.Content["name"])
	}

	return nil
}
