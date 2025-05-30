package service

import (
	"ada/backend/apiserver/api/rpc"
	v2 "ada/backend/apiserver/api/v2"
	aCommon "ada/backend/apiserver/common"
	"ada/backend/apiserver/server"
	"ada/backend/apiserver/util"
	"ada/backend/cache"
	baseCommon "ada/backend/common"
	"ada/backend/model"
	"ada/infra/ldap"
	"ada/infra/mongo"
	"context"
	"fmt"
	"strings"
	"time"

	ldap3 "github.com/go-ldap/ldap/v3"
	jsoniter "github.com/json-iterator/go"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *ADAServiceV2) ListDomain(ctx context.Context, in *v2.ListDomainReq) (*v2.ListDomainReply, error) {
	// 1、MongoDB 查询(分页)
	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)
	res, total, err := server.FindAllDomain(s.env, int64(limit), int64(offset), in.FilterDomain, in.FilterStatus, in.FilterKeyword)
	if err != nil {
		logger.Errorf("query list domain err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("QueryFailed"))
	}
	// 2、结果返回(带域账户信息)
	ret := v2.ListDomainReply{}
	for _, r := range res {
		r.LdapConf["password"] = "*******"

		// Create domain details
		domainDetails := &v2.ListDomainReply_Details{
			ID:         r.ID.Hex(),
			Name:       r.Name,
			DcHostname: r.DCHostName,
			Status:     r.Status,
			DomainInfo: r.LdapConf,
			CreateTm:   r.CreateTm.String(),
			ErrMsg:     r.ErrMsg,
		}

		// Add DC list if available
		if len(r.DCList) > 0 {
			for _, dc := range r.DCList {
				dcItem := &v2.ListDomainReplyDcList{
					Hostname:     dc.HostName,
					Platform:     dc.Platform,
					Version:      dc.Version,
					Ips:          strings.Join(dc.IPList, ","),
					Timeout:      dc.Timeout,
					Status:       dc.Status,
					HasSensor:    dc.HasSensor,
					IsMaster:     dc.IsMaster,
					FsmoRole:     dc.FsmoRole,
					ErrMsg:       dc.ErrMsg,
					LastOnlineTm: dc.LastOnlineTm.String(),
				}

				domainDetails.DCs = append(domainDetails.DCs, dcItem)
			}
		}

		ret.List = append(ret.List, domainDetails)
	}

	ret.Page = &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: int32(total)}
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	} else {
		ret.Exhausted = true
	}
	return &ret, nil
}

func (s *ADAServiceV2) AddDomain(ctx context.Context, in *v2.AddDomainReq) (*v2.AddDomainReply, error) {
	// 1、 is super and domain not exist
	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}
	//2、LDAP数据解析 和用户密码AES加密
	domain, _, dcHostName, dn, err := util.LDAPParse(in.LdapAddr)
	if err != nil {
		logger.Warnf("ldap parse err:%v", err)
		return nil, status.Error(codes.InvalidArgument, s.I18n("ParseFailed"))
	}

	dcHostName = strings.ToUpper(dcHostName)
	domain = strings.ToLower(domain)

	//domain exists
	_, err = server.CheckDomain(s.env, dcHostName, domain)
	if err != mongo.ErrNotFound {
		logger.Warnf("already exists err:%v", err)
		return nil, status.Error(codes.InvalidArgument, s.I18n("AlreadyExists"))
	}

	passwordEncrypt, err := util.PasswordEncrypt(in.Password)
	if err != nil {
		logger.Errorf("ldap password encrypt err:%v", err)
		return nil, status.Error(codes.InvalidArgument, s.I18n("Domain.PasswordSaveError"))
	}
	//3、MongoDB 存储 Redis 存储(序列化 set key="域名")
	ldapConf := map[string]string{
		"server":   in.LdapAddr,
		"user":     in.Username,
		"password": passwordEncrypt,
		"dn":       dn,
		"dns":      in.DNS,
	}

	err = server.AddDomain(s.env, domain, dcHostName, baseCommon.DomainStatusInit, ldapConf)
	if err != nil {
		logger.Errorf("ldap password encrypt err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("Domain.PasswordSaveError"))
	}

	// add scan conf for this domain in tb_scan_conf.plans
	err = server.UpdateScanConfByDomain(s.env, domain, false)
	if err != nil {
		logger.Errorf("update scan_conf by domain(%s) err:%v", domain, err)
		return nil, status.Error(codes.Internal, s.I18n("Domain.UpdateScanConfFailed"))
	}

	var ldapCache = cache.LDAPAccount{
		Server:   in.LdapAddr,
		User:     in.Username,
		Password: passwordEncrypt,
		Dn:       dn,
		DNS:      in.DNS,
	}
	ldapCacheStr, _ := jsoniter.MarshalToString(&ldapCache)
	err = s.env.RedisCli.Set(ctx, cache.LDAPAccountKey(domain), ldapCacheStr, 0).Err()
	if err != nil {
		logger.Errorf("redis cli save ldap cache err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}
	// update domain list and domain name list
	err = s.env.RedisCli.SAdd(ctx, cache.DomainListKey(), strings.ToLower(domain)).Err()
	if err != nil {
		logger.Errorf("redis cli save domain list err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}

	client, err := rpc.NewClient(ctx, s.env.Cfg.BindSrv.TaskAddr)
	if err != nil {
		logger.Errorf("new rpc client err:%v", err)
	} else {
		defer client.Close()
		_, err = client.DomainStatusSyncTask()
		if err != nil {
			logger.Warnf("send domain status sync task err:%v", err)
		}

		_, err = client.DomainLdapSyncTask()
		if err != nil {
			logger.Warnf("send domain ldap sync task err:%v", err)
		}
	}

	return &v2.AddDomainReply{Result: aCommon.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) UpdateDomainData(ctx context.Context, in *v2.UpdateDomainDataReq) (*v2.UpdateDomainDataReply, error) {
	ret := &v2.UpdateDomainDataReply{
		Result: aCommon.RESP_FAILED,
	}
	//domain exists
	domainInfo, err := server.GetDomainById(s.env, in.DomainID)
	if err != nil || domainInfo == nil {
		logger.Errorf("get domain by id err:%v", err)
		return ret, status.Error(codes.InvalidArgument, s.I18n("Domain.DomainStatusError"))
	}

	ldapAddr, ok := domainInfo.LdapConf["server"]
	if !ok {
		return ret, status.Error(codes.InvalidArgument, s.I18n("Domain.UpdateDomainData.LDAPAddrError"))
	}
	user, ok := domainInfo.LdapConf["user"]
	if !ok {
		return ret, status.Error(codes.InvalidArgument, s.I18n("Domain.InvalidCredentials"))
	}
	password, ok := domainInfo.LdapConf["password"]
	if !ok {
		return ret, status.Error(codes.InvalidArgument, s.I18n("Domain.InvalidCredentials"))
	}
	password, err = util.PasswordDecode(password)
	if err != nil {
		logger.Warnf("password decode err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("Domain.InvalidCredentials"))
	}
	dns, ok := domainInfo.LdapConf["dns"]
	if !ok {
		return ret, status.Error(codes.InvalidArgument, s.I18n("Domain.DomainStatusError"))
	}
	_, err = ldap.GetConn(ldapAddr, user, password, dns)
	if err != nil {
		return ret, status.Error(codes.InvalidArgument, s.I18n("Domain.DomainStatusError"))
	}

	ret.Result = aCommon.RESP_SUCCESS
	return ret, nil
}

func (s *ADAServiceV2) TestDomain(ctx context.Context, in *v2.TestDomainReq) (*v2.TestDomainReply, error) {
	//1、域服务器连接测试
	ret := &v2.TestDomainReply{Status: 0}
	// 如果前端没有传递密码，则从数据库解析密码
	if in.Password == "*******" {
		domain, err := server.GetPwdByLdapAddr(s.env, in.LdapAddr)
		if err != nil {
			logger.Warnf("get domain password by ldap addr err:%v", err)
			return ret, status.Error(codes.Internal, s.I18n("Domain.InvalidCredentials"))
		}
		in.Password, err = util.PasswordDecode(domain.LdapConf["password"])
		if err != nil {
			logger.Warnf("password decode err:%v", err)
			return ret, status.Error(codes.Internal, s.I18n("Domain.InvalidCredentials"))
		}
	}

	ch := make(chan error, 1)

	go func() {
		_, err := ldap.GetConn(in.LdapAddr, in.Username, in.Password, in.DNS)
		ch <- err
	}()

	select {
	case err := <-ch:
		//2、测试结果返回(状态和错误信息) 85
		var msg string
		if err != nil {
			logger.Warnf("test ldap err:%v", err)
			switch {
			case ldap3.IsErrorWithCode(err, ldap3.LDAPResultInvalidCredentials):
				msg = s.I18n("Domain.TestDomain.TestErrorInvalidCredentials")
			case ldap3.IsErrorWithCode(err, ldap3.ErrorNetwork):
				msg = s.I18n("Domain.TestDomain.TestErrorNetwork")
			case ldap3.IsErrorWithCode(err, ldap3.LDAPResultTimeout):
				msg = s.I18n("Domain.TestDomain.TestErrorTimeout")
			default:
				msg = s.I18n("Domain.TestDomain.TestErrorUnknown")
			}
			ret := v2.TestDomainReply{Status: 0, Msg: msg}
			return &ret, nil
		}
	case <-time.After(time.Second * 10):
		ret.Msg = s.I18n("Domain.TestDomain.TestErrorTimeout")
		return ret, nil
	}
	return &v2.TestDomainReply{Status: 1, Msg: s.I18n("Domain.TestDomain.TestSuccess")}, nil
}

func (s *ADAServiceV2) UpdateDomain(ctx context.Context, in *v2.UpdateDomainReq) (*v2.UpdateDomainReply, error) {
	//1、 is super
	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	//domain exists
	domainInfo, err := server.GetDomainById(s.env, in.ID)
	if err != nil || domainInfo == nil {
		logger.Errorf("already exists err:%v", err)
		return nil, status.Error(codes.InvalidArgument, s.I18n("NotFound"))
	}

	//删除旧domain ldap config
	err = s.env.RedisCli.Del(ctx, cache.LDAPAccountKey(domainInfo.Name)).Err()
	if err != nil {
		logger.Errorf("redis delete domain key:%v err:%v", domainInfo.Name, err)
		return nil, status.Error(codes.Internal, s.I18n("Domain.UpdateDomain.DeleteKeyFailed"))
	}

	//2、LDAP数据解析 和用户密码AES加密
	domain, _, dcHostName, dn, err := util.LDAPParse(in.LdapAddr)
	if err != nil {
		logger.Errorf("ldap parse err:%v", err)
		return nil, status.Error(codes.InvalidArgument, s.I18n("Domain.UpdateDomain.LDAPParseFailed"))
	}

	if in.Password == "*******" {
		password := domainInfo.LdapConf["password"]
		in.Password, err = util.PasswordDecode(password)
		if err != nil {
			logger.Errorf("ldap password encrypt err:%v", err)
			return nil, status.Error(codes.InvalidArgument, s.I18n("Domain.PasswordEncryptError"))
		}
	}

	enCodePassWord, err := util.PasswordEncrypt(in.Password)
	if err != nil {
		logger.Errorf("ldap password encrypt err:%v", err)
		return nil, status.Error(codes.InvalidArgument, s.I18n("Domain.PasswordEncryptError"))
	}
	//3、MongoDB(根据ID更新) Redis(序列化 key=域名) 更新
	ldapConf := map[string]string{
		"server":   in.LdapAddr,
		"user":     in.Username,
		"password": enCodePassWord,
		"dn":       dn,
		"dns":      in.DNS,
	}

	err = server.UpdateDomain(s.env, in.ID, strings.ToLower(domain), strings.ToUpper(dcHostName), domainInfo.Status, ldapConf, domainInfo.DCList)
	if err != nil {
		logger.Errorf("update domain err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("UpdateFailed"))
	}

	// update scan conf for this domain in tb_scan_conf.plans
	err = server.UpdateScanConfByDomainV2(s.env, domainInfo.Name, domain)
	if err != nil {
		logger.Errorf("update scan_conf by domain(%s) err:%v", domain, err)
		return nil, status.Error(codes.Internal, s.I18n("Domain.UpdateScanConfFailed"))
	}

	var ldapCache = cache.LDAPAccount{
		Server:   in.LdapAddr,
		User:     in.Username,
		Password: enCodePassWord,
		Dn:       dn,
		DNS:      in.DNS,
	}

	ldapCacheStr, _ := jsoniter.MarshalToString(&ldapCache)
	err = s.env.RedisCli.Set(ctx, cache.LDAPAccountKey(domainInfo.Name), ldapCacheStr, 0).Err()
	if err != nil {
		logger.Errorf("redis save ldap cache err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}

	// 下发域同步任务
	client, err := rpc.NewClient(ctx, s.env.Cfg.BindSrv.TaskAddr)
	if err != nil {
		logger.Errorf("new rpc client err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("RpcClientFailed"))
	}
	defer client.Close()

	_, err = client.DomainStatusSyncTask()
	if err != nil {
		logger.Errorf("send domain status sync task err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("Domain.UpdateDomain.StatusSyncTaskFailed"))
	}

	_, err = client.DomainLdapSyncTask()
	if err != nil {
		logger.Errorf("send domain ldap sync task err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("Domain.UpdateDomain.LDAPSyncTaskFailed"))
	}

	//删除旧domain
	err = s.env.RedisCli.SRem(ctx, cache.DomainListKey(), strings.ToLower(domainInfo.Name)).Err()
	if err != nil {
		logger.Errorf("redis delete domain list err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}

	// update domain list and domain dc name list
	err = s.env.RedisCli.SAdd(ctx, cache.DomainListKey(), strings.ToLower(domain)).Err()
	if err != nil {
		logger.Errorf("redis update domain list err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}

	//update domain entry domain name(更新敏感组)
	//err = server.UpdateDomainEntryByName(s.env, domainInfo.Name, domain)
	//if err != nil {
	//	logger.Errorf("update domain entry err:%v", err)
	//	return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	//}

	return &v2.UpdateDomainReply{Result: aCommon.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) DeleteDomain(ctx context.Context, in *v2.DeleteDomainReq) (*v2.DeleteDomainReply, error) {
	//1、 is super
	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	domainInfo, err := server.GetDomainById(s.env, in.ID)
	if err != nil || domainInfo == nil {
		logger.Errorf("already exists err:%v", err)
		return nil, status.Error(codes.InvalidArgument, s.I18n("NotFound"))
	}

	//2、MongoDB(根据ID删除)
	err = server.DeleteDomain(s.env, in.ID)
	if err != nil {
		logger.Errorf("delete domain err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("DeleteFailed"))
	}

	// remove scan conf for this domain in tb_scan_conf.plans
	err = server.UpdateScanConfByDomain(s.env, domainInfo.Name, true)
	if err != nil {
		logger.Errorf("update scan_conf by domain(%s) err:%v", domainInfo.Name, err)
		return nil, status.Error(codes.Internal, s.I18n("UpdateFailed"))
	}

	//删除敏感组配置
	//err = server.DeleteAllDomainEntry(s.env, in.Name)
	//if err != nil {
	//	logger.Warnf("delete domain entry err:%v", err)
	//}

	//3、Redis(Key=域名) 删除
	err = s.env.RedisCli.Del(ctx, cache.LDAPAccountKey(in.Name)).Err()
	if err != nil {
		logger.Errorf("redis delete domain key:%v err:%v", in.Name, err)
		return nil, status.Error(codes.Internal, s.I18n("DeleteKeyFailed"))
	}
	//4、删除domain list and domain dc name list
	err = s.env.RedisCli.SRem(ctx, cache.DomainListKey(), strings.ToLower(in.Name)).Err()
	if err != nil {
		logger.Errorf("redis cli delete domain list err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}
	err = s.env.RedisCli.Del(ctx, cache.DomainIPRelateDCKey(in.Name)).Err()
	if err != nil {
		logger.Errorf("redis cli delete domain info cache err:%v", err)
	}

	// 删除域后调用域同步，主要解决关于域资产同步时删除域不及时的问题
	client, err := rpc.NewClient(ctx, s.env.Cfg.BindSrv.TaskAddr)
	if err == nil {
		defer client.Close()
		_, err = client.DomainStatusSyncTask()
		if err != nil {
			logger.Warnf("send domain status sync task err:%v", err)
		}
	} else {
		logger.Warnf("new rpc client err:%v", err)
	}

	return &v2.DeleteDomainReply{Result: aCommon.RESP_SUCCESS}, nil
}

// DeploySensor deploy sensor to domain dc server automatically(using winrm protocol)
func (s *ADAServiceV2) DeploySensor(ctx context.Context, in *v2.DeploySensorReq) (*v2.DeploySensorReply, error) {
	//1、is super
	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	sysInfo, err := server.GetSystemInfo(s.env)
	if err != nil {
		logger.Errorf("get system info err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}

	//2、get domain info
	domainInfo, err := server.GetDomainById(s.env, in.DomainID)
	if err != nil || domainInfo == nil {
		logger.Errorf("get domain by id err:%v", err)
		return nil, status.Error(codes.InvalidArgument, s.I18n("NotFound"))
	}

	//3、get dc info from domainInfo.DCList
	var targetDC *model.DCList
	for i, dc := range domainInfo.DCList {
		if dc.HostName == in.DcHostname {
			targetDC = &domainInfo.DCList[i]
			break
		}
	}

	if targetDC == nil {
		logger.Errorf("dc hostname %s not found in domain", in.DcHostname)
		return nil, status.Error(codes.InvalidArgument, s.I18n("Domain.DeploySensor.DcHostnameNotFound"))
	}

	//4. check dc hostname status is online('run')
	if targetDC.Status != "run" {
		logger.Errorf("dc hostname %s status is not online", in.DcHostname)
		return nil, status.Error(codes.InvalidArgument, s.I18n("Domain.DeploySensor.DcHostnameNotOnline"))
	}

	//5.confirm dc hostname is not install sensor
	if targetDC.HasSensor {
		logger.Errorf("dc hostname %s already has sensor installed", in.DcHostname)
		return nil, status.Error(codes.InvalidArgument, s.I18n("Domain.DeploySensor.SensorAlreadyInstalled"))
	}

	// Get LDAP account credentials for WinRM
	ldapConf := domainInfo.LdapConf
	username := ldapConf["user"]
	password, err := util.PasswordDecode(ldapConf["password"])
	if err != nil {
		logger.Errorf("password decode err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("Domain.DeploySensor.PasswordDecodeError"))
	}

	// note: username format can't be: CHINA.COM\administrator, it must be: administrator@china.com(for winrm protocol)
	if strings.Contains(username, "\\") {
		parts := strings.Split(username, "\\")
		if len(parts) == 2 {
			username = fmt.Sprintf("%s@%s", parts[1], domainInfo.Name)
		}
	}

	// Get DC IP for WinRM connection
	if len(targetDC.IPList) == 0 {
		logger.Errorf("dc hostname %s has no IP addresses", in.DcHostname)
		return nil, status.Error(codes.InvalidArgument, s.I18n("Domain.DeploySensor.DcHostnameNoIP"))
	}

	installStdout, err := s.winRMInstallSensor(ctx, targetDC.IPList, sysInfo.SystemIP, username, password)
	if err != nil {
		logger.Errorf("winrm install sensor err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("Domain.DeploySensor.SensorInstallationFailed"))
	}

	//8.check install_adaegis.ps1 is success
	// Look for success message in output
	if !strings.Contains(installStdout, "Installation successful") {
		logger.Errorf("installation not successful, stdout:%s", installStdout)
		return nil, status.Error(codes.Internal, s.I18n("Domain.DeploySensor.SensorInstallationFailed"))
	}

	// Update sensor status in DB
	err = server.UpdateDCHasSensor(s.env, in.DomainID, in.DcHostname, true)
	if err != nil {
		logger.Errorf("update dc sensor status err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("UpdateFailed"))
	}

	return &v2.DeploySensorReply{Result: aCommon.RESP_SUCCESS}, nil
}
