package service

import (
	"ada/infra/license"
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/common"
	"ada/backend/apiserver/server"
	"ada/backend/apiserver/util"
	"ada/backend/model"

	logger "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const tokenExpired = 60 * 5
const fileMaxSize = 512 * 1024

// needChangePwdTm 提醒用户修改密码周期
const needChangePwdTm = 60 * 24 * time.Hour

var UserLoginCountInfo model.UserBucket

func init() {
	UserLoginCountInfo.List = make(map[string]*model.UserLoginCountInfo)
}

func (s *ADAServiceV2) Login(ctx context.Context, in *v2.LoginReq) (*v2.LoginReply, error) {
	user, err := server.GetUser(s.env, in.Username)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "无效的用户名或密码")
	}

	clt := UserLoginCountInfo.Get(in.Username)
	if clt.LoginErrCount >= common.LoginErrorCount {
		return nil, status.Errorf(codes.PermissionDenied, "登录错误锁定五分钟")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(in.Password))
	if err != nil {
		_ = UserLoginCountInfo.SetLoginErrCount(in.Username, 1)
		return nil, status.Errorf(codes.Unauthenticated, "无效的用户名或密码")
	}

	if user.MfaStatus == "enable" && in.TotpCode == "" {
		return nil, status.Error(codes.PermissionDenied, "未输入二次验证")
	}

	// 新增二次验证判断
	if user.MfaStatus == "enable" {
		totpCode, err := strconv.Atoi(in.TotpCode)
		if err != nil {
			logger.Errorf("strconv atoi err:%v", err)
			return nil, status.Error(codes.Unauthenticated, "输入的验证码错误")
		}

		check := util.TotpCheck(user.Secret, totpCode)
		if !check {
			_ = UserLoginCountInfo.SetLoginErrCount(in.Username, 1)

			return nil, status.Error(codes.Unauthenticated, "验证码错误")
		}
	}

	// If the login is successful, the error changes to 0
	_ = UserLoginCountInfo.SetLoginErrCount(in.Username, 0)
	// generate jwt-token
	exp := time.Now().Add(time.Minute * tokenExpired).Unix()
	token, err := util.GenerateToken(in.Username, user.Role, user.Priv, exp)
	// Write LastLoginExpireTime
	UserLoginCountInfo.SetLastLoginExpireTime(in.Username, exp)
	if err != nil {
		return nil, status.Error(codes.Internal, "验证生成异常")
	}

	licer, err := license.NewAdaLicense(s.env.RedisCli)
	if err != nil {
		logger.Errorf("new license client err:%v", err)
		return nil, status.Error(codes.Internal, "服务器内部错误")
	}
	if licer.Expired() {
		logger.Errorf("license expired, will exit!")
		return nil, status.Error(codes.Aborted, "许可证已过期")
	}

	var needChangePwd bool
	t := user.PwdUpdateTm
	if t.IsZero() {
		t = user.CreateTm
	}
	if time.Since(t) >= needChangePwdTm {
		logger.Debugf("用户[%s]已超过60天未更新密码", user.UserName)
		needChangePwd = true
	}

	userInfo := v2.LoginReply{
		ID:            user.ID,
		Username:      user.UserName,
		Role:          user.Role,
		Priv:          user.Priv,
		Mobile:        user.Mobile,
		Email:         user.Email,
		Remark:        user.Remark,
		Token:         token,
		NeedChangePwd: needChangePwd,
	}

	return &userInfo, nil
}

func (s *ADAServiceV2) Logout(ctx context.Context, in *v2.LogoutReq) (*v2.LogoutReply, error) {
	// passed
	return &v2.LogoutReply{Result: common.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) ListUser(ctx context.Context, in *v2.ListUserReq) (*v2.ListUserReply, error) {
	username := s.GetUser(ctx)

	// 如果是管理员查询子用户列表，则清空查询条件
	if s.IsSuper(ctx) && !in.IsSelf {
		username = ""
	}

	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)
	res, total, err := server.FindAllUser(s.env, limit, offset, in.Search, username, in.FilterRole, in.FilterMfaStatus, in.FilterPassStrength, in.FilterStartCreateTm, in.FilterEndCreateTm, in.FilterStartPassTm, in.FilterEndPassTm, in.Sort)
	if err != nil {
		logger.Errorf("Query ListUser err:%v", err)
		return nil, status.Error(codes.Internal, "查询用户列表发生错误")
	}

	ret := v2.ListUserReply{}

	for _, r := range res {
		ret.List = append(ret.List,
			&v2.ListUserReply_Details{
				ID:           r.ID,
				Username:     r.UserName,
				PassStrength: r.PassStrength,
				Role:         r.Role,
				Priv:         r.Priv,
				Mobile:       r.Mobile,
				Email:        r.Email,
				Remark:       r.Remark,
				CreateTm:     r.CreateTm.String(),
				HasMfa:       r.MfaStatus == "enable", // 是否开启二次验证
				Avatar:       r.Avatar,
				PwdUpdateTm: func(u *model.User) string {
					if u.PwdUpdateTm.IsZero() {
						return u.CreateTm.String()
					}
					return u.PwdUpdateTm.String()
				}(&r),
				RealName:   r.RealName,
				Address:    r.Address,
				Department: r.Department,
				Post:       r.Post,
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

func (s *ADAServiceV2) AddUser(ctx context.Context, in *v2.AddUserReq) (*v2.AddUserReply, error) {
	if in.Username == "" || in.Password == "" {
		return nil, status.Errorf(codes.Internal, "用户名和密码不能为空")
	}
	if in.Role == "" {
		return nil, status.Errorf(codes.PermissionDenied, "权限不能为空")
	}

	var pri int32 = common.PrivUser
	if in.Role == "mgr" {
		pri = common.PrivSuper
	}

	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, "没有操作权限")
	}
	_, err := server.GetUser(s.env, in.Username)
	if err == nil {
		return nil, status.Error(codes.Internal, "用户名已存在")
	}
	if len(in.Password) < 8 {
		return nil, status.Error(codes.Internal, "密码长度不符合要求，请输入8位以上密码")
	}

	plainPwd, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Errorf("encrypt password err:%v", err)
		return nil, status.Error(codes.Internal, "服务端内部错误")
	}

	passStrength := util.CheckPassStrength(in.Password)
	err = server.AddUser(s.env, in.Username, string(plainPwd), passStrength, in.Role, in.Mobile, in.Email, in.Remark, in.RealName, in.Department, in.Address, in.Post, pri)
	if err != nil {
		logger.Errorf("add user err:%v", err)
		return nil, status.Errorf(codes.Internal, "新增用户失败")
	}

	return &v2.AddUserReply{Result: common.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) UpdateUser(ctx context.Context, in *v2.UpdateUserReq) (*v2.UpdateUserReply, error) {
	_, err := server.GetUser(s.env, in.Username)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "无效的用户名或密码")
	}

	user, err := server.FindUserByName(s.env, in.Username)
	if err != nil {
		logger.Errorf("find user by name err:%v", err)
		return nil, status.Errorf(codes.Unauthenticated, "获取用户信息失败")
	}
	user.Role = in.Role
	user.Mobile = in.Mobile
	user.Email = in.Email
	user.Remark = in.Remark
	user.RealName = in.RealName
	user.Post = in.Post
	user.Department = in.Department
	user.Address = in.Address
	err = server.UpdateUser(s.env, user)
	if err != nil {
		logger.Errorf("update user err:%v", err)
		return nil, status.Errorf(codes.Internal, "更新用户信息失败")
	}
	return &v2.UpdateUserReply{Result: common.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) UpdateUserPassword(ctx context.Context, in *v2.UpdateUserPasswordReq) (*v2.UpdateUserPasswordReply, error) {
	//is super
	var userName string
	if !s.IsSuper(ctx) {
		userName = s.GetUser(ctx)
	} else {
		userName = in.Username
	}
	//get user info and checkout old password
	user, err := server.GetUser(s.env, userName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "无效的用户名或密码")
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(in.OldPassword))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "无效的用户名或密码")
	}
	if len(in.NewPassword) < 8 {
		return nil, status.Errorf(codes.InvalidArgument, "密码长度过短，请输入8位以上密码")
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.MinCost)
	if err != nil {
		logger.Errorf("encrypt password err:%v", err)
		return nil, status.Errorf(codes.Internal, "加密过程异常，请重试")
	}
	passStrength := util.CheckPassStrength(in.NewPassword)
	err = server.UpdateUserPassword(s.env, in.Username, string(passwordHash), passStrength)
	if err != nil {
		logger.Errorf("update password err:%v", err)
		return nil, status.Errorf(codes.Internal, "修改密码失败")
	}
	return &v2.UpdateUserPasswordReply{Result: common.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) DeleteUser(ctx context.Context, in *v2.DeleteUserReq) (*v2.DeleteUserReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}
	users, err := server.GetUser(s.env, in.Username)
	if err != nil || users == nil {
		return nil, status.Errorf(codes.Unauthenticated, "用户名已存在")
	}
	selfName := s.GetUser(ctx)
	if selfName == in.Username {
		return nil, status.Errorf(codes.Internal, "不能删除自己")
	}
	err = server.DeleteUser(s.env, in.Username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "删除用户失败")
	}
	return &v2.DeleteUserReply{Result: common.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) CheckMfa(ctx context.Context, in *v2.CheckMfaReq) (*v2.CheckMfaReply, error) {
	user, err := server.GetUser(s.env, in.Username)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "无效的用户名或密码")
	}

	clt := UserLoginCountInfo.Get(in.Username)

	if clt.LoginErrCount >= common.LoginErrorCount {
		return nil, status.Errorf(codes.PermissionDenied, "登录错误次数达到上限,您的账户被锁五分钟")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(in.Password))
	if err != nil {
		_ = UserLoginCountInfo.SetLoginErrCount(in.Username, 1)

		return nil, status.Error(codes.Unauthenticated, "无效的用户名或密码")
	}

	// 如果该字段存在值，则说明需要输入code
	if user.MfaStatus == "enable" {
		return &v2.CheckMfaReply{HasMfa: true}, nil
	}

	return &v2.CheckMfaReply{HasMfa: false}, nil
}

func (s *ADAServiceV2) EnableMfa(ctx context.Context, in *v2.EnableMfaReq) (*v2.EnableMfaReply, error) {
	userName := in.Username
	secret := in.Secret
	code := in.MfaCode
	passWord := in.Password

	if len(code) < 6 {
		return nil, status.Errorf(codes.Internal, "参数异常")
	}

	user, err := server.GetUser(s.env, userName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "账户异常，请重试")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(passWord))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "用户密码错误")
	}

	mfaCode, err := strconv.Atoi(in.MfaCode)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "参数异常")
	}
	ok := util.TotpCheck(secret, mfaCode)
	if !ok {
		return nil, status.Errorf(codes.Internal, "验证码错误")
	}

	user.Secret = secret
	err = server.UpdateUserSecret(s.env, user)
	if err != nil {
		logger.Errorf("update user secret err:%v", err)
		return nil, err
	}

	return &v2.EnableMfaReply{Result: "SUCCESS"}, nil
}

func (s *ADAServiceV2) DisableMfa(ctx context.Context, in *v2.DisableMfaReq) (*v2.DisableMfaReply, error) {
	username := in.Username

	if username == "" {
		return nil, status.Errorf(codes.Unauthenticated, "无效的用户名")
	}

	user, err := server.GetUser(s.env, username)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "无效的用户名")
	}

	err = server.DisableMfa(s.env, user)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "禁用失败")
	}

	return &v2.DisableMfaReply{}, nil
}

func (s *ADAServiceV2) UpdateAvatar(ctx context.Context, in *v2.UpdateAvatarReq) (*v2.UpdateAvatarReply, error) {
	var allowFileType = map[string]int{
		"JPG":  1,
		"JPEG": 1,
		"PNG":  1,
	}

	file := in.File
	ret := &v2.UpdateAvatarReply{
		Result: common.RESP_FAILED,
	}

	bytes, err := base64.StdEncoding.DecodeString(file)
	if err != nil {
		logger.Errorf("decode string err: %s", err)
		return ret, status.Error(codes.Internal, "上传头像失败")
	}

	if len(bytes)/8 > fileMaxSize {
		return ret, status.Error(codes.Internal, "上传头像文件过大，请上传小于512Kb的图片文件")
	}

	// 类型限制
	contentType := http.DetectContentType(bytes)
	fileType := strings.Split(contentType, "/")[1]
	if _, ok := allowFileType[strings.ToUpper(fileType)]; !ok {
		return ret, status.Error(codes.Internal, "仅限上传JPG，JPEG，PNG格式的图片文件")
	}

	err = server.UpdateUserAvatar(s.env, in.UserId, file)
	if err != nil {
		logger.Errorf("update avatar err:%v", err)
		return ret, status.Error(codes.Internal, "修改头像失败")
	}

	ret.Result = common.RESP_SUCCESS

	return ret, nil
}

func (s *ADAServiceV2) ResetPassword(ctx context.Context, in *v2.ResetPasswordReq) (*v2.ResetPasswordReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.Internal, "没有操作权限")
	}

	if len(in.NewPassword) < 8 {
		return nil, status.Errorf(codes.Internal, "请输入长度大于8位的密码")
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.MinCost)
	if err != nil {
		logger.Errorf("encrypt password err:%v", err)
		return nil, status.Errorf(codes.Internal, "修改密码失败")
	}

	passStrength := util.CheckPassStrength(in.NewPassword)
	err = server.UpdateUserPassword(s.env, in.Username, string(passwordHash), passStrength)
	if err != nil {
		logger.Errorf("update password err:%v", err)
		return nil, status.Errorf(codes.Internal, "修改密码失败")
	}

	return &v2.ResetPasswordReply{Result: common.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) GetPwdUpdateTm(ctx context.Context, in *v2.GetPwdUpdateTmReq) (*v2.GetPwdUpdateTmReply, error) {
	user, err := server.GetUser(s.env, in.GetUserName())
	if err != nil {
		logger.Errorf("get user info by name fail. error: %s", err)
		return nil, status.Errorf(codes.Internal, "未能找到用户信息")
	}
	var b bool
	if user.PwdUpdateTm.IsZero() {
		user.PwdUpdateTm = user.CreateTm
	}
	if time.Since(user.PwdUpdateTm) > needChangePwdTm {
		b = true
	}
	return &v2.GetPwdUpdateTmReply{
		NeedChangePwd: b,
		PwdUpdateTm:   user.PwdUpdateTm.String(),
	}, nil
}

func (s *ADAServiceV2) UserExists(ctx context.Context, in *v2.UserExistsReq) (*v2.UserExistsReply, error) {
	_, err := server.GetUser(s.env, in.Username)
	if err == nil {
		return &v2.UserExistsReply{
			Result: true,
		}, nil
	}

	return &v2.UserExistsReply{
		Result: false,
	}, nil
}
