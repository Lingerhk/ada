package worker

import (
	"ada/backend/apiserver/util"
	"ada/backend/cache"
	"ada/backend/common"
	"ada/backend/model"
	"ada/infra/ldap"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	ldap3 "github.com/go-ldap/ldap/v3"
	jsoniter "github.com/json-iterator/go"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// DomainSyncTask 同步域控制器、传感器状态
func (w *Worker) DomainSyncTask() error {
	lang := w.GetLanguage()

	// 1 同步域状态
	isSame, err := syncDomainStatus(w, lang)
	if err != nil {
		logger.Warnf("sync domain status err:%v", err)
	}

	if !isSame {
		err = syncDomainDCList(w)
		if err != nil {
			logger.Warnf("sync domain dc list err:%v", err)
		}
	}

	return nil
}

func syncDomainStatus(w *Worker, lang string) (bool, error) {
	isSame := true

	domainStatusMap := make(map[string]string)
	domainList, err := getDomainListByStatus(w, "")
	if err != nil {
		logger.Warnf("get domain err: %v", err)
		return true, err
	}

	wg := sync.WaitGroup{}
	for _, domain := range domainList {
		wg.Add(1)
		domain := domain
		domainStatusMap[domain.Name] = domain.Status
		go func() {
			defer wg.Done()
			domainStatus, errMsg, dcList := getDomainStatus(w, domain, lang)
			if errMsg != "" {
				logger.Warnf("check domain status failed, Id: %s, error: %+v", domain.ID.Hex(), errMsg)
			}

			// 判断DCList是否发生变化
			if !sliceEqual(domain.DCList, dcList) {
				isSame = false
			}

			domain.Status = domainStatus
			domain.ErrMsg = errMsg
			domain.DCList = dcList

			if err := updateDomainByID(w, domain); err != nil {
				logger.Warnf("sync domain status failed, Id: %s, error: %+v", domain.ID.Hex(), err)
			}

			// 如果域状态从从运行变为其他状态则需要发送通知
			if domainStatusMap[domain.Name] == "run" && domainStatus != "run" {
				var lastTm = time.Now()
				for _, dc := range dcList {
					if strings.EqualFold(dc.HostName, domain.DCHostName) {
						lastTm = dc.LastOnlineTm
						break
					}
				}

				// 发送域控离线提醒。 6小时内不再重复提醒
				ctx := context.Background()
				name := fmt.Sprintf("%s.%s", domain.DCHostName, domain.Name)
				lastNotifyKey := fmt.Sprintf("ada:server:notify_ttl_domain_%s", name)
				if w.env.RedisCli.Exists(ctx, lastNotifyKey).Val() == 0 {
					title := fmt.Sprintf("%s:%s", getNotifyMsgTypeDesc(common.NotifyMsgSystem, lang), getI18n("domain_status_abnormal", lang))
					desc := fmt.Sprintf(getI18n("domain_status_abnormal_desc", lang), name, lastTm.Format("2006:01:02 15:04:05"))
					params := map[string]string{"last_online_tm": lastTm.Format("2006:01:02 15:04:05"), "dc_hostname": name}
					err = AddNotify(w.env.MongoCli, title, "domain", desc, lang, params)
					// update domain_last_notify_tm
					_ = w.env.RedisCli.Set(ctx, lastNotifyKey, "1", 6*time.Hour).Err()
				}
			}
		}()
	}
	wg.Wait()
	return isSame, nil
}

// 获取域控制器状态
func getDomainStatus(w *Worker, domain model.Domain, lang string) (string, string, []model.DCList) {
	dns := domain.LdapConf["dns"]
	passWord, _ := util.PasswordDecode(domain.LdapConf["password"])
	userName := domain.LdapConf["user"]

	dcHostnameList := []string{domain.DCHostName}
	if len(domain.DCList) > 0 {
		for _, dc := range domain.DCList {
			if dc.HostName == domain.DCHostName {
				continue
			}
			dcHostnameList = append(dcHostnameList, dc.HostName)
		}
	}

	// 遍历dcHostnameList查询域控列表，优先从添加域的dc进行获取
	DCList, err := getDomainDCListWithLDAP(dcHostnameList, domain.Name, userName, passWord, dns)
	if err != nil {
		if len(DCList) == 0 {
			var dcList []model.DCList
			for _, dc := range domain.DCList {
				dcList = append(dcList, model.DCList{
					HostName:     dc.HostName,
					Platform:     dc.Platform,
					IPList:       dc.IPList,
					Timeout:      "0ms",
					Status:       common.DomainStatusErr,
					HasSensor:    false,
					IsMaster:     false, // TODO: update me
					FsmoRole:     "",    // TODO: update me
					ErrMsg:       getI18n("ldap_connect_failed", lang),
					LastOnlineTm: time.Now(),
				})
			}
			return "error", getI18n("get_domain_dc_list_failed", lang), dcList
		}
	}

	domainStatus := common.DomainStatusStopped
	var domainErrMsg string
	for k := range DCList {
		dcStatus := common.DomainStatusStopped
		dc := &DCList[k]
		timeOut := connDCTimeOut(*dc)
		dialURL := fmt.Sprintf("ldap://%s.%s", dc.HostName, domain.Name)
		errMsg := checkLdapConn(dialURL, userName, passWord, dns, lang)
		if errMsg == "" {
			dcStatus = common.DomainStatusRunning
		}

		if strings.EqualFold(dc.HostName, domain.DCHostName) {
			domainErrMsg = errMsg
			domainStatus = dcStatus
		}
		dc.Timeout = timeOut
		dc.ErrMsg = errMsg
		dc.Status = dcStatus
		dc.HasSensor = isSensorInstalled(w, dc.HostName)
		dc.LastOnlineTm = time.Now()
	}
	return domainStatus, domainErrMsg, DCList
}

func checkLdapConn(dialURL, userName, passWord, dns, lang string) string {
	_, err := ldap.GetConn(dialURL, userName, passWord, dns)
	if err != nil {
		errMsg := ""
		switch {
		case ldap3.IsErrorWithCode(err, ldap3.LDAPResultInvalidCredentials):
			errMsg = getI18n("invalid_username_or_password", lang)
		case ldap3.IsErrorWithCode(err, ldap3.ErrorNetwork):
			errMsg = getI18n("ldap_address_error", lang)
		case ldap3.IsErrorWithCode(err, ldap3.LDAPResultTimeout):
			errMsg = getI18n("connection_timeout_check_dns", lang)
		default:
			errMsg = fmt.Sprintf(getI18n("unknown_error", lang), err)
		}

		return errMsg
	}
	return ""
}

func syncDomainDCList(e *Worker) error {
	domainList, err := getDomainListByStatus(e, "")
	if err != nil {
		logger.Warnf("find all domain list err:%v", err)
		return err
	}

	ctx := context.Background()

	for _, domain := range domainList {
		if len(domain.DCList) == 0 { // 如果没有DC列表则不进行更新
			continue
		}

		var ipRelateMap = make(map[string]any)

		for _, dc := range domain.DCList {
			dcFullName := fmt.Sprintf("%s.%s", strings.ToLower(dc.HostName), domain.Name)
			for _, ip := range dc.IPList {
				err = e.env.RedisCli.Set(ctx, cache.DomainIPRelateDCNameKey(ip), dcFullName, 0).Err()
				if err != nil {
					logger.Errorf("redis set domain ip relate dc name cache err:%v, will ignore it!", err)
				}
				ipRelateMap[ip] = dcFullName
			}
		}

		err = e.env.RedisCli.Del(ctx, cache.DomainIPRelateDCKey(domain.Name)).Err()
		if err != nil {
			logger.Errorf("redis cli delete domain info cache err:%v, will ignore it!", err)
		}

		err = e.env.RedisCli.HMSet(ctx, cache.DomainIPRelateDCKey(domain.Name), ipRelateMap).Err()
		if err != nil {
			logger.Errorf("redis update domain dc_name_list err:%v", err)
			continue
		}
	}

	return nil
}

func getDomainListByStatus(e *Worker, status string) ([]model.Domain, error) {
	domain := model.Domain{}
	var domainList []model.Domain

	query := bson.M{}
	if status != "" {
		query = bson.M{"status": status}
	}

	err := e.env.MongoCli.FindAll(domain.CollectName(), query, &domainList)
	if err != nil {
		return nil, err
	}

	return domainList, nil
}

// 同步域控制器状态
func updateDomainByID(w *Worker, domain model.Domain) error {
	return w.env.MongoCli.UpdateById(domain.CollectName(), domain.ID, &domain)
}

func getSensorByDCHostName(w *Worker, dcHostName string) (*model.Sensor, error) {
	query := bson.M{"dc_hostname": strings.ToLower(dcHostName)}
	var sensor model.Sensor
	err, _ := w.env.MongoCli.FindOne(sensor.CollectName(), query, &sensor)
	if err != nil {
		return nil, err
	}
	return &sensor, nil
}

func sliceEqual(oldList, newList []model.DCList) bool {
	if len(oldList) != len(newList) {
		return false
	}
	slices.SortFunc(oldList, func(a, b model.DCList) int {
		return strings.Compare(b.HostName, a.HostName)
	})

	slices.SortFunc(newList, func(a, b model.DCList) int {
		return strings.Compare(b.HostName, a.HostName)
	})

	for k := range oldList {
		slices.Sort(oldList[k].IPList)
		slices.Sort(newList[k].IPList)

		oldByte, _ := jsoniter.Marshal(oldList)
		newByte, _ := jsoniter.Marshal(newList)

		if !bytes.Equal(oldByte, newByte) {
			return false
		}
	}

	return true
}

func getDomainDCListWithLDAP(dcHostnameList []string, domainName, username, password, dns string) ([]model.DCList, error) {
	// DNS查询该DC对应的IP列表
	resolver := net.Resolver{}
	if dns != "" {
		resolver = net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: time.Millisecond * time.Duration(10000)}
				return d.DialContext(ctx, "udp", fmt.Sprintf("%s:53", dns))
			},
		}
	}

	var domain string
	var ldapSearch *ldap.LDAPSearch

	hasConned := false
	for _, dcHostname := range dcHostnameList {
		ldapAddr := fmt.Sprintf("ldap://%s.%s", dcHostname, domainName)
		l, err := url.Parse(ldapAddr)
		if err != nil {
			logger.Warnf("parse ldapAddr(%s) err:%v, continue.", ldapAddr, err)
			continue
		}

		parts := strings.Split(l.Host, ".")
		if len(parts) < 3 {
			logger.Warnf("invalid ldapAddr(%s), continue.", ldapAddr)
			continue
		}

		domain = strings.Join(parts[1:], ".")
		// LDAP查询该域内的所有DC列表
		dnPrefix := ""
		logger.Printf("ldap params:ldapAddr:%s, username:%s, password:%s, dns:%s\n", ldapAddr, username, password, dns)
		ldapSearch, err = ldap.NewSearch(ldapAddr, username, password, dns, dnPrefix)
		if err != nil {
			logger.Warnf("neNewSearch(%s) err:%v, continue.", ldapAddr, err)
			continue
		}
		defer ldapSearch.Close()

		hasConned = true
		break
	}

	if !hasConned {
		return nil, fmt.Errorf("ldap connect all dc failed(domain:%s)", domainName)
	}

	entriesList, err := ldapSearch.LdapSearchDomainController()
	if err != nil {
		return nil, err
	}

	pdcName, err := ldapSearch.LdapSearchFSMORoleOwner()
	if err != nil {
		logger.Warnf("ldap search fsmo role owner err:%v, will ignore it!", err)
	}

	var DCList []model.DCList
	for _, entries := range entriesList {
		var ipList []string
		dcHostName := entries.Attributes[0].Values[0]
		platform := entries.Attributes[2].Values[0]
		version := entries.Attributes[3].Values[0]
		dcAddr := fmt.Sprintf("%s.%s", entries.Attributes[0].Values[0], domain)
		ips, err := resolver.LookupIP(context.Background(), "ip", dcAddr)
		if err != nil {
			logger.Warnf("look upda up err:%v", err)
			continue
		}

		for _, ip := range ips {
			ipList = append(ipList, ip.String())
		}

		isMaster := false
		fsmoRole := "DC"
		if pdcName == dcHostName {
			fsmoRole = "PDC"
			isMaster = true
		}

		DCList = append(DCList, model.DCList{HostName: dcHostName, FsmoRole: fsmoRole, IsMaster: isMaster, IPList: ipList, Platform: platform, Version: version})
	}

	return DCList, nil
}

func connDCTimeOut(dc model.DCList) string {
	for _, ip := range dc.IPList {
		tm, err := pinger(ip)
		if err != nil {
			logger.Warnf("pinger err:%v", err)
			continue
		}
		return tm
	}
	return ""
}

func pinger(ip string) (string, error) {
	startTime := time.Now()
	target := fmt.Sprintf("%s:135", ip)
	conn, err := net.DialTimeout("tcp", target, time.Second*3)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var t = float64(time.Since(startTime)) / float64(time.Millisecond)
	return fmt.Sprintf("%4.2fms", t), nil
}

func isSensorInstalled(w *Worker, dcHostName string) bool {
	sensor, err := getSensorByDCHostName(w, dcHostName)
	if err != nil || sensor == nil {
		logger.Warnf("get sensor by dc_hostname(%s) err:%v", dcHostName, err)
		return false
	}

	return true
}
