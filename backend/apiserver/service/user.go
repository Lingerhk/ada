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

const tokenExpired = 60 * 12 // jwt token expire time in minutes
const fileMaxSize = 512 * 1024
const loginErrorExpire = 60 * 5 // 5 minutes for login error tracking

// needChangePwdTm 提醒用户修改密码周期
const needChangePwdTm = 90 * 24 * time.Hour

// Redis keys for login tracking
func userLoginErrorKey(username string) string {
	return "ada:server:user_login:errors:" + username
}

func userLoginExpireKey(username string) string {
	return "ada:server:user_login:expire:" + username
}

// getLoginErrorCount gets the login error count from Redis
func (s *ADAServiceV2) getLoginErrorCount(ctx context.Context, username string) int {
	val, err := s.env.RedisCli.Get(ctx, userLoginErrorKey(username)).Int()
	if err != nil {
		return 0
	}
	return val
}

// incrLoginErrorCount increments the login error count in Redis
func (s *ADAServiceV2) incrLoginErrorCount(ctx context.Context, username string) error {
	key := userLoginErrorKey(username)
	pipe := s.env.RedisCli.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, time.Duration(loginErrorExpire)*time.Second)
	_, err := pipe.Exec(ctx)
	return err
}

// resetLoginErrorCount resets the login error count in Redis
func (s *ADAServiceV2) resetLoginErrorCount(ctx context.Context, username string) error {
	return s.env.RedisCli.Del(ctx, userLoginErrorKey(username)).Err()
}

// setLastLoginExpireTime sets the last login expire time in Redis
func (s *ADAServiceV2) setLastLoginExpireTime(ctx context.Context, username string, expireTime int64) error {
	return s.env.RedisCli.Set(ctx, userLoginExpireKey(username), expireTime, 0).Err()
}

func (s *ADAServiceV2) Login(ctx context.Context, in *v2.LoginReq) (*v2.LoginReply, error) {
	user, err := server.GetUser(s.env, in.Username)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, s.I18n("User.Login.InvalidCredentials"))
	}

	loginErrCount := s.getLoginErrorCount(ctx, in.Username)
	if loginErrCount >= common.LoginErrorCount {
		return nil, status.Error(codes.PermissionDenied, s.I18n("User.LoginErrorLocked"))
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(in.Password))
	if err != nil {
		_ = s.incrLoginErrorCount(ctx, in.Username)
		return nil, status.Error(codes.Unauthenticated, s.I18n("User.Login.InvalidCredentials"))
	}

	if user.MfaStatus == "enable" && in.TotpCode == "" {
		return nil, status.Error(codes.PermissionDenied, s.I18n("User.Login.EmptyMfaCode"))
	}

	// 新增二次验证判断
	if user.MfaStatus == "enable" {
		totpCode, err := strconv.Atoi(in.TotpCode)
		if err != nil {
			logger.Errorf("strconv atoi err:%v", err)
			return nil, status.Error(codes.Unauthenticated, s.I18n("User.Login.MfaCodeError"))
		}

		check := util.TotpCheck(user.Secret, totpCode)
		if !check {
			_ = s.incrLoginErrorCount(ctx, in.Username)

			return nil, status.Error(codes.Unauthenticated, s.I18n("User.Login.MfaCodeError"))
		}
	}

	// If the login is successful, reset the error count
	_ = s.resetLoginErrorCount(ctx, in.Username)
	// generate jwt-token
	exp := time.Now().Add(time.Minute * tokenExpired).Unix()
	token, err := util.GenerateToken(in.Username, user.Role, user.Priv, exp)
	// Write LastLoginExpireTime
	_ = s.setLastLoginExpireTime(ctx, in.Username, exp)
	if err != nil {
		return nil, status.Error(codes.Internal, s.I18n("User.Login.MfaCodeGenerateError"))
	}

	licer, err := license.NewAdaLicense(s.env.RedisCli)
	if err != nil {
		logger.Errorf("new license client err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}
	if licer.Expired() {
		logger.Errorf("license expired, will exit!")
		return nil, status.Error(codes.Aborted, s.I18n("LicenseExpired"))
	}

	var needChangePwd bool
	t := user.PwdUpdateTm
	if t.IsZero() {
		t = user.CreateTm
	}
	if time.Since(t) >= needChangePwdTm {
		logger.Debugf("user(%s) password has not updated for more than 90 days", user.UserName)
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
		return nil, status.Error(codes.Internal, s.I18n("QueryFailed"))
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
		return nil, status.Error(codes.InvalidArgument, s.I18n("User.AddUser.UsernameAndPasswordEmpty"))
	}
	if in.Role == "" {
		return nil, status.Error(codes.InvalidArgument, s.I18n("User.AddUser.RoleEmpty"))
	}

	var pri int32 = common.PrivUser
	if in.Role == "mgr" {
		pri = common.PrivSuper
	}

	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}
	_, err := server.GetUser(s.env, in.Username)
	if err == nil {
		return nil, status.Error(codes.AlreadyExists, s.I18n("User.UsernameExists"))
	}
	if len(in.Password) < 8 {
		return nil, status.Error(codes.Internal, s.I18n("User.PasswordLengthError"))
	}

	plainPwd, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Errorf("encrypt password err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}

	passStrength := util.CheckPassStrength(in.Password)
	err = server.AddUser(s.env, in.Username, string(plainPwd), passStrength, in.Role, in.Mobile, in.Email, in.Remark, in.RealName, in.Department, in.Address, in.Post, pri)
	if err != nil {
		logger.Errorf("add user err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("User.AddUser.AddUserFailed"))
	}

	return &v2.AddUserReply{Result: common.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) UpdateUser(ctx context.Context, in *v2.UpdateUserReq) (*v2.UpdateUserReply, error) {
	_, err := server.GetUser(s.env, in.Username)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, s.I18n("User.InvalidUsernameOrPassword"))
	}

	user, err := server.FindUserByName(s.env, in.Username)
	if err != nil {
		logger.Errorf("find user by name err:%v", err)
		return nil, status.Error(codes.Unauthenticated, s.I18n("User.UpdateUser.GetUserInfoFailed"))
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
		return nil, status.Error(codes.Internal, s.I18n("User.UpdateUser.UpdateUserFailed"))
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
		return nil, status.Error(codes.Internal, s.I18n("User.InvalidUsernameOrPassword"))
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(in.OldPassword))
	if err != nil {
		return nil, status.Error(codes.Internal, s.I18n("User.InvalidUsernameOrPassword"))
	}
	if len(in.NewPassword) < 8 {
		return nil, status.Error(codes.Internal, s.I18n("User.PasswordLengthError"))
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.MinCost)
	if err != nil {
		logger.Errorf("encrypt password err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("User.UpdateUserPassword.EncryptPasswordError"))
	}
	passStrength := util.CheckPassStrength(in.NewPassword)
	err = server.UpdateUserPassword(s.env, in.Username, string(passwordHash), passStrength)
	if err != nil {
		logger.Errorf("update password err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("User.UpdateUserPassword.UpdatePasswordFailed"))
	}
	return &v2.UpdateUserPasswordReply{Result: common.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) DeleteUser(ctx context.Context, in *v2.DeleteUserReq) (*v2.DeleteUserReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}
	users, err := server.GetUser(s.env, in.Username)
	if err != nil || users == nil {
		return nil, status.Error(codes.NotFound, s.I18n("User.UsernameExists"))
	}
	selfName := s.GetUser(ctx)
	if selfName == in.Username {
		return nil, status.Error(codes.PermissionDenied, s.I18n("User.DeleteUser.CannotDeleteSelf"))
	}
	err = server.DeleteUser(s.env, in.Username)
	if err != nil {
		return nil, status.Error(codes.Internal, s.I18n("User.DeleteUser.DeleteUserFailed"))
	}
	return &v2.DeleteUserReply{Result: common.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) CheckMfa(ctx context.Context, in *v2.CheckMfaReq) (*v2.CheckMfaReply, error) {
	user, err := server.GetUser(s.env, in.Username)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, s.I18n("User.InvalidUsernameOrPassword"))
	}

	loginErrCount := s.getLoginErrorCount(ctx, in.Username)
	if loginErrCount >= common.LoginErrorCount {
		return nil, status.Error(codes.PermissionDenied, s.I18n("User.LoginErrorLocked"))
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(in.Password))
	if err != nil {
		_ = s.incrLoginErrorCount(ctx, in.Username)

		return nil, status.Error(codes.Unauthenticated, s.I18n("User.InvalidUsernameOrPassword"))
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
		return nil, status.Error(codes.InvalidArgument, s.I18n("InvalidArgument"))
	}

	user, err := server.GetUser(s.env, userName)
	if err != nil {
		return nil, status.Error(codes.Internal, s.I18n("User.InvalidUsername"))
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(passWord))
	if err != nil {
		return nil, status.Error(codes.Internal, s.I18n("User.InvalidPassword"))
	}

	mfaCode, err := strconv.Atoi(in.MfaCode)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, s.I18n("InvalidArgument"))
	}
	ok := util.TotpCheck(secret, mfaCode)
	if !ok {
		return nil, status.Error(codes.Internal, s.I18n("User.InvalidMfaCode"))
	}

	user.Secret = secret
	err = server.UpdateUserSecret(s.env, user)
	if err != nil {
		logger.Errorf("update user secret err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("User.EnableMfa.UpdateSecretFailed"))
	}

	return &v2.EnableMfaReply{Result: "SUCCESS"}, nil
}

func (s *ADAServiceV2) DisableMfa(ctx context.Context, in *v2.DisableMfaReq) (*v2.DisableMfaReply, error) {
	username := in.Username

	if username == "" {
		return nil, status.Error(codes.Unauthenticated, s.I18n("User.InvalidUsername"))
	}

	user, err := server.GetUser(s.env, username)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, s.I18n("User.InvalidUsername"))
	}

	err = server.DisableMfa(s.env, user)
	if err != nil {
		return nil, status.Error(codes.Internal, s.I18n("User.DisableMfa.DisableFailed"))
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
		return ret, status.Error(codes.Internal, s.I18n("User.UpdateAvatar.UploadFailed"))
	}

	if len(bytes)/8 > fileMaxSize {
		return ret, status.Error(codes.InvalidArgument, s.I18n("User.UpdateAvatar.FileTooLarge"))
	}

	// 类型限制
	contentType := http.DetectContentType(bytes)
	fileType := strings.Split(contentType, "/")[1]
	if _, ok := allowFileType[strings.ToUpper(fileType)]; !ok {
		return ret, status.Error(codes.InvalidArgument, s.I18n("User.UpdateAvatar.InvalidFileType"))
	}

	err = server.UpdateUserAvatar(s.env, in.UserId, file)
	if err != nil {
		logger.Errorf("update avatar err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("UpdateFailed"))
	}

	ret.Result = common.RESP_SUCCESS

	return ret, nil
}

func (s *ADAServiceV2) ResetPassword(ctx context.Context, in *v2.ResetPasswordReq) (*v2.ResetPasswordReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	if len(in.NewPassword) < 8 {
		return nil, status.Error(codes.InvalidArgument, s.I18n("User.PasswordLengthError"))
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.MinCost)
	if err != nil {
		logger.Errorf("encrypt password err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("User.UpdateUserPassword.EncryptPasswordError"))
	}

	passStrength := util.CheckPassStrength(in.NewPassword)
	err = server.UpdateUserPassword(s.env, in.Username, string(passwordHash), passStrength)
	if err != nil {
		logger.Errorf("update password err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("UpdateFailed"))
	}

	return &v2.ResetPasswordReply{Result: common.RESP_SUCCESS}, nil
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