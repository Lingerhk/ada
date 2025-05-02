package service

import (
	"ada/backend/apiserver/api/rpc"
	v2 "ada/backend/apiserver/api/v2"
	aCommon "ada/backend/apiserver/common"
	"ada/backend/apiserver/server"
	"ada/backend/apiserver/util"
	"ada/backend/cache"
	baseCommon "ada/backend/common"
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
		return nil, status.Errorf(codes.Internal, "查询失败")
	}
	// 2、结果返回(带域账户信息)
	ret := v2.ListDomainReply{}
	for _, r := range res {
		r.LdapConf["password"] = "*******"
		ret.List = append(ret.List,
			&v2.ListDomainReply_Details{
				ID:         r.ID.Hex(),
				Name:       r.Name,
				DcHostname: r.DCHostName,
				Status:     r.Status,
				DomainInfo: r.LdapConf,
				CreateTm:   r.CreateTm.String(),
				ErrMsg:     r.ErrMsg,
			})
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
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}
	//2、LDAP数据解析 和用户密码AES加密
	domain, _, dcHostName, dn, err := util.LDAPParse(in.LdapAddr)
	if err != nil {
		logger.Warnf("ldap parse err:%v", err)
		return nil, status.Errorf(codes.InvalidArgument, "解析失败")
	}

	dcHostName = strings.ToUpper(dcHostName)
	domain = strings.ToLower(domain)

	//domain exists
	_, err = server.CheckDomain(s.env, dcHostName, domain)
	if err != mongo.ErrNotFound {
		logger.Warnf("already exists err:%v", err)
		return nil, status.Errorf(codes.InvalidArgument, "已经存在")
	}

	passwordEncrypt, err := util.PasswordEncrypt(in.Password)
	if err != nil {
		logger.Errorf("ldap password encrypt err:%v", err)
		return nil, status.Errorf(codes.InvalidArgument, "密码存储异常")
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
		return nil, status.Errorf(codes.Internal, "密码存储异常")
	}

	// add scan conf for this domain in tb_scan_conf.plans
	err = server.UpdateScanConfByDomain(s.env, domain, false)
	if err != nil {
		logger.Errorf("update scan_conf by domain(%s) err:%v", domain, err)
		return nil, status.Errorf(codes.Internal, "更新扫描配置失败")
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
		return nil, status.Errorf(codes.Internal, "系统错误")
	}
	// update domain list and domain name list
	err = s.env.RedisCli.SAdd(ctx, cache.DomainListKey(), strings.ToLower(domain)).Err()
	if err != nil {
		logger.Errorf("redis cli save domain list err:%v", err)
		return nil, status.Errorf(codes.Internal, "系统错误")
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
		return ret, status.Errorf(codes.InvalidArgument, "域状态异常")
	}

	ldapAddr, ok := domainInfo.LdapConf["server"]
	if !ok {
		return ret, status.Errorf(codes.InvalidArgument, "ldap地址错误")
	}
	user, ok := domainInfo.LdapConf["user"]
	if !ok {
		return ret, status.Errorf(codes.InvalidArgument, "用户名或密码不正确")
	}
	password, ok := domainInfo.LdapConf["password"]
	if !ok {
		return ret, status.Errorf(codes.InvalidArgument, "用户名或密码不正确")
	}
	password, err = util.PasswordDecode(password)
	if err != nil {
		logger.Warnf("password decode err:%v", err)
		return ret, status.Error(codes.Internal, "用户名或密码不正确")
	}
	dns, ok := domainInfo.LdapConf["dns"]
	if !ok {
		return ret, status.Errorf(codes.InvalidArgument, "域状态异常")
	}
	_, err = ldap.GetConn(ldapAddr, user, password, dns)
	if err != nil {
		return ret, status.Errorf(codes.InvalidArgument, "域状态异常")
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
			return ret, status.Error(codes.Internal, "用户名或密码不正确")
		}
		in.Password, err = util.PasswordDecode(domain.LdapConf["password"])
		if err != nil {
			logger.Warnf("password decode err:%v", err)
			return ret, status.Error(codes.Internal, "用户名或密码不正确")
		}
	}

	ch := make(chan error, 1)

	go func() {
		_, err := ldap.GetConn(in.LdapAddr, in.Username, in.Password, in.DNS)
		ch <- err
	}()

	msg := "测试错误:%v"
	select {
	case err := <-ch:
		//2、测试结果返回(状态和错误信息) 85
		if err != nil {
			logger.Warnf("test ldap err:%v", err)
			switch {
			case ldap3.IsErrorWithCode(err, ldap3.LDAPResultInvalidCredentials):
				msg = fmt.Sprintf(msg, "用户名或密码不正确")
			case ldap3.IsErrorWithCode(err, ldap3.ErrorNetwork):
				msg = fmt.Sprintf(msg, "ldap地址错误")
			case ldap3.IsErrorWithCode(err, ldap3.LDAPResultTimeout):
				msg = fmt.Sprintf(msg, "连接超时，请检查DNS地址是否正确")
			case ldap3.IsErrorWithCode(err, ldap3.LDAPResultTimeout):
			default:
				msg = fmt.Sprintf(msg, "未知的错误")
			}
			ret := v2.TestDomainReply{Status: 0, Msg: msg}
			return &ret, nil
		}
	case <-time.After(time.Second * 10):
		ret.Msg = fmt.Sprintf(msg, "连接超时，请检查DNS地址是否正确")
		return ret, nil
	}
	return &v2.TestDomainReply{Status: 1, Msg: "测试成功"}, nil
}

func (s *ADAServiceV2) UpdateDomain(ctx context.Context, in *v2.UpdateDomainReq) (*v2.UpdateDomainReply, error) {
	//1、 is super
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}

	//domain exists
	domainInfo, err := server.GetDomainById(s.env, in.ID)
	if err != nil || domainInfo == nil {
		logger.Errorf("already exists err:%v", err)
		return nil, status.Errorf(codes.InvalidArgument, "不存在")
	}

	//删除旧domain ldap config
	err = s.env.RedisCli.Del(ctx, cache.LDAPAccountKey(domainInfo.Name)).Err()
	if err != nil {
		logger.Errorf("redis delete domain key:%v err:%v", domainInfo.Name, err)
		return nil, status.Errorf(codes.Internal, "删除域密钥失败")
	}

	//2、LDAP数据解析 和用户密码AES加密
	domain, _, dcHostName, dn, err := util.LDAPParse(in.LdapAddr)
	if err != nil {
		logger.Errorf("ldap parse err:%v", err)
		return nil, status.Errorf(codes.InvalidArgument, "验证失败")
	}

	if in.Password == "*******" {
		password := domainInfo.LdapConf["password"]
		in.Password, err = util.PasswordDecode(password)
		if err != nil {
			logger.Errorf("ldap password encrypt err:%v", err)
			return nil, status.Errorf(codes.InvalidArgument, "加密异常")
		}
	}

	enCodePassWord, err := util.PasswordEncrypt(in.Password)
	if err != nil {
		logger.Errorf("ldap password encrypt err:%v", err)
		return nil, status.Errorf(codes.InvalidArgument, "加密异常")
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
		return nil, status.Errorf(codes.Internal, "更新域失败")
	}

	// update scan conf for this domain in tb_scan_conf.plans
	err = server.UpdateScanConfByDomainV2(s.env, domainInfo.Name, domain)
	if err != nil {
		logger.Errorf("update scan_conf by domain(%s) err:%v", domain, err)
		return nil, status.Errorf(codes.Internal, "更新扫描配置失败")
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
		return nil, status.Errorf(codes.Internal, "redis保存状态失败")
	}

	// 下发域同步任务
	client, err := rpc.NewClient(ctx, s.env.Cfg.BindSrv.TaskAddr)
	if err != nil {
		logger.Errorf("new rpc client err:%v", err)
		return nil, status.Errorf(codes.Internal, "服务器内部错误")
	}
	defer client.Close()

	_, err = client.DomainStatusSyncTask()
	if err != nil {
		logger.Errorf("send domain status sync task err:%v", err)
		return nil, status.Errorf(codes.Internal, "域状态同步任务任务失败")
	}

	_, err = client.DomainLdapSyncTask()
	if err != nil {
		logger.Errorf("send domain ldap sync task err:%v", err)
		return nil, status.Errorf(codes.Internal, "域资产同步任务任务失败")
	}

	//删除旧domain
	err = s.env.RedisCli.SRem(ctx, cache.DomainListKey(), strings.ToLower(domainInfo.Name)).Err()
	if err != nil {
		logger.Errorf("redis delete domain list err:%v", err)
		return nil, status.Errorf(codes.Internal, "系统错误")
	}

	// update domain list and domain dc name list
	err = s.env.RedisCli.SAdd(ctx, cache.DomainListKey(), strings.ToLower(domain)).Err()
	if err != nil {
		logger.Errorf("redis update domain list err:%v", err)
		return nil, status.Errorf(codes.Internal, "系统错误")
	}

	//update domain entry domain name(更新敏感组)
	//err = server.UpdateDomainEntryByName(s.env, domainInfo.Name, domain)
	//if err != nil {
	//	logger.Errorf("update domain entry err:%v", err)
	//	return nil, status.Errorf(codes.Internal, "系统错误")
	//}

	return &v2.UpdateDomainReply{Result: aCommon.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) DeleteDomain(ctx context.Context, in *v2.DeleteDomainReq) (*v2.DeleteDomainReply, error) {
	//1、 is super
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}

	domainInfo, err := server.GetDomainById(s.env, in.ID)
	if err != nil || domainInfo == nil {
		logger.Errorf("already exists err:%v", err)
		return nil, status.Errorf(codes.InvalidArgument, "目标域控不存在")
	}

	//2、MongoDB(根据ID删除)
	err = server.DeleteDomain(s.env, in.ID)
	if err != nil {
		logger.Errorf("delete domain err:%v", err)
		return nil, status.Errorf(codes.Internal, "删除域失败")
	}

	// remove scan conf for this domain in tb_scan_conf.plans
	err = server.UpdateScanConfByDomain(s.env, domainInfo.Name, true)
	if err != nil {
		logger.Errorf("update scan_conf by domain(%s) err:%v", domainInfo.Name, err)
		return nil, status.Errorf(codes.Internal, "更新扫描配置失败")
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
		return nil, status.Errorf(codes.Internal, "删除域密钥失败")
	}
	//4、删除domain list and domain dc name list
	err = s.env.RedisCli.SRem(ctx, cache.DomainListKey(), strings.ToLower(in.Name)).Err()
	if err != nil {
		logger.Errorf("redis cli delete domain list err:%v", err)
		return nil, status.Errorf(codes.Internal, "系统错误")
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
