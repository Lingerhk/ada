package service

import (
	"ada/backend/apiserver/util"
	"ada/backend/model"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/common"
	"ada/backend/apiserver/config"
	"ada/backend/apiserver/server"
	bCommon "ada/backend/common"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// return status
const (
	RESP_SUCCESS = "success"
	RESP_FAILED  = "failed"
)

const (
	_abortIndex  int8 = math.MaxInt8 / 2
	_headerAuthz      = "authorization"
	_bearer           = "Bearer"
)

var (
	_whitelist = []string{
		"/ada.ADA/Login",
		"/ada.ADA/CheckMfa",
		"/ada.ADA/Logout",
		"/ada.ADA/GetLicence",
		"/ada.ADA/UpdateLicence",
	}

	// accessKeyActiveTmCache tracks the last time ActiveTm was updated for each AccessKey ID
	// to avoid updating the database on every request (throttled to 5 minutes)
	accessKeyActiveTmCache    = make(map[string]time.Time)
	accessKeyActiveTmMutex    sync.RWMutex
	accessKeyActiveTmThrottle = 5 * time.Minute

	// userActiveTmCache tracks the last time ActiveTm was updated for each User
	// to avoid updating the database on every request (throttled to 5 minutes)
	userActiveTmCache    = make(map[string]time.Time)
	userActiveTmMutex    sync.RWMutex
	userActiveTmThrottle = 5 * time.Minute
)

// ADA grpc service struct
type ADAServiceV2 struct {
	env      *config.Env
	language string // system language: EN/ZH
}

// GrpcService is the grpc server and its configurations.
type GrpcService struct {
	env      *config.Env
	server   *grpc.Server
	handlers []grpc.UnaryServerInterceptor
}

// getLastLoginExpireTime gets the last login expire time from Redis
func (s *GrpcService) getLastLoginExpireTime(ctx context.Context, username string) (int64, error) {
	s = s.withContext(ctx)
	return s.env.RedisCli.Get(ctx, userLoginExpireKey(username)).Int64()
}

// updateUserActiveTm updates the User's ActiveTm field with throttling
func (s *GrpcService) updateUserActiveTm(username string) error {
	shouldUpdate := false

	userActiveTmMutex.RLock()
	lastUpdate, exists := userActiveTmCache[username]
	userActiveTmMutex.RUnlock()

	if !exists || time.Since(lastUpdate) >= userActiveTmThrottle {
		shouldUpdate = true
	}

	if shouldUpdate {
		// Update the ActiveTm field in database
		now := time.Now()
		var u model.User
		update := bson.M{"$set": bson.M{"active_tm": now}}
		err := s.env.MongoCli.UpdateRaw(s.env.MongoContext(), u.CollectName(), bson.M{"username": username}, &update, false)
		if err != nil {
			logger.Errorf("Failed to update user active_tm for %s: %v", username, err)
			return err
		}

		// Update cache
		userActiveTmMutex.Lock()
		userActiveTmCache[username] = now
		userActiveTmMutex.Unlock()
	}

	return nil
}

// authenticateByAccessKey authenticates user by AccessKey secret hash
func (s *GrpcService) authenticateByAccessKey(secretHash string) (*util.UserClaim, error) {
	var accessKey model.AccessKey
	tb := (&model.AccessKey{}).CollectName()

	// Query active AccessKey by secret hash
	query := bson.M{
		"secret_hash": secretHash,
		"status":      "active",
	}

	err, exist := s.env.MongoCli.FindOne(s.env.MongoContext(), tb, query, &accessKey)
	if err != nil {
		logger.Errorf("Failed to query AccessKey: %v", err)
		return nil, fmt.Errorf("authentication failed")
	}

	if !exist {
		return nil, fmt.Errorf("invalid access key")
	}

	username := accessKey.Username

	// Update ActiveTm with throttling (only update if last update was more than 5 minutes ago)
	accessKeyID := accessKey.ID.Hex()
	shouldUpdate := false

	accessKeyActiveTmMutex.RLock()
	lastUpdate, exists := accessKeyActiveTmCache[accessKeyID]
	accessKeyActiveTmMutex.RUnlock()

	if !exists || time.Since(lastUpdate) >= accessKeyActiveTmThrottle {
		shouldUpdate = true
	}

	if shouldUpdate {
		// Update the ActiveTm field in database
		now := time.Now()
		accessKey.ActiveTm = now
		err = s.env.MongoCli.UpdateById(s.env.MongoContext(), tb, accessKey.ID, &accessKey)
		if err != nil {
			logger.Warnf("Failed to update AccessKey ActiveTm for %s: %v", accessKeyID, err)
			// Don't fail authentication if we can't update the timestamp
		} else {
			// Update cache
			accessKeyActiveTmMutex.Lock()
			accessKeyActiveTmCache[accessKeyID] = now
			accessKeyActiveTmMutex.Unlock()
		}
	}

	// Get user info to construct UserClaim
	var user model.User
	err, exist = s.env.MongoCli.FindOne(s.env.MongoContext(), user.CollectName(), bson.M{"username": username}, &user)
	if err != nil || !exist {
		logger.Errorf("Failed to get user info for username %s: %v", username, err)
		return nil, fmt.Errorf("user not found")
	}

	// Construct UserClaim for AccessKey authentication
	userClaim := &util.UserClaim{
		User: user.UserName,
		Role: user.Role,
		Priv: int(user.Priv),
		// For AccessKey, we don't check expiration, so set a far future time
		Expired: time.Now().Add(24 * time.Hour).Unix(),
	}

	return userClaim, nil
}

// New news a GrpcService using customized configurations.
func New(env *config.Env, opt ...grpc.ServerOption) *GrpcService {
	keepAlive := grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionIdle:     time.Second * 600,
		MaxConnectionAge:      time.Hour * 2,
		MaxConnectionAgeGrace: time.Second * 20,
		Time:                  time.Second * 300,
		Timeout:               time.Second * 20,
	})

	s := new(GrpcService)
	s.env = env

	lang := getSysLanguage(env)

	opt = append(opt, keepAlive, grpc.UnaryInterceptor(s.interceptor))
	opt = append(opt, grpc.MaxRecvMsgSize(1024*1024*32))
	opt = append(opt, grpc.MaxSendMsgSize(1024*1024*32))

	s.server = grpc.NewServer(opt...)
	s.Use(s.recovery(), s.handle(), s.logging(), s.validate())

	v2.RegisterADAServer(s.server, &ADAServiceV2{env, lang})

	return s
}

// Start starts the grpc server.
func (s *GrpcService) Start(address string) error {
	logger.Infof("starting grpc service at: %s", address)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	reflection.Register(s.server)
	return s.server.Serve(listener)
}

// Stop stops the grpc server.
func (s *GrpcService) Stop() {
	s.server.Stop()
}

// Execution is done in left-to-right order, including passing of context.
// For example ChainUnaryServer(one, two, three) will execute one before two before three, and three
// will see context changes of one and two.
func (s *GrpcService) interceptor(ctx context.Context, req any,
	args *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	var (
		i     int
		chain grpc.UnaryHandler
	)

	n := len(s.handlers)
	if n == 0 {
		return handler(ctx, req)
	}

	chain = func(ic context.Context, ir any) (any, error) {
		if i == n-1 {
			return handler(ic, ir)
		}
		i++
		return s.handlers[i](ic, ir, args, chain)
	}

	return s.handlers[0](ctx, req, args, chain)
}

// Use attachs a global inteceptor to the server.
// For example, this is the right place for a rate limiter or error management inteceptor
func (s *GrpcService) Use(handlers ...grpc.UnaryServerInterceptor) *GrpcService {
	finalSize := len(s.handlers) + len(handlers)
	if finalSize >= int(_abortIndex) {
		remaining := int(_abortIndex) - len(s.handlers)
		if remaining <= 0 {
			logger.Errorf("grpc service: interceptor limit reached (%d), ignoring %d handlers", _abortIndex, len(handlers))
			return s
		}

		logger.Errorf("grpc service: interceptor limit reached (%d), truncating %d handlers to %d", _abortIndex, len(handlers), remaining)
		handlers = handlers[:remaining]
		finalSize = len(s.handlers) + len(handlers)
	}
	mergedHandlers := make([]grpc.UnaryServerInterceptor, finalSize)
	copy(mergedHandlers, s.handlers)
	copy(mergedHandlers[len(s.handlers):], handlers)
	s.handlers = mergedHandlers

	return s
}

// recovery is a server interceptor that recovers from any panics.
func (s *GrpcService) recovery() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, args *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if rerr := recover(); rerr != nil {
				buf := make([]byte, 1024*32) // 32KB
				_ = runtime.Stack(buf, false)
				logger.Errorf("grpc server panic: %v\n%v\n%s\n", req, rerr, buf)
				err = status.Errorf(codes.Unknown, "panic recovered: %v", rerr)
			}
		}()
		resp, err = handler(ctx, req)
		return
	}
}

// handle return a new unary server interceptor for Tracing\LinkTimeout\AuthToken
func (s *GrpcService) handle() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, args *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {
		s = s.withContext(ctx)
		// Check if grpc FullMethod is in the whitelist first
		if slices.Contains(_whitelist, args.FullMethod) {
			return handler(ctx, req) // Pass original context for whitelisted methods
		}

		// For non-whitelisted methods, proceed with auth and other logic using the timed context
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.InvalidArgument, "Invalid Argument")
		}

		// 获取 header 的`authorization: Bearer token`字段的值
		var token string
		if val, ok := md[_headerAuthz]; ok {
			splits := strings.SplitN(val[0], " ", 2)
			if len(splits) < 2 || splits[0] != _bearer {
				return nil, status.Error(codes.Unauthenticated, "Unauthenticated")
			}
			token = splits[1]
		}

		// Try to parse as JWT token first
		var u *util.UserClaim
		u, err = util.ParseToken(token, common.JWT_SECRET)
		if err != nil {
			// If it's an invalid JWT token error, try AccessKey authentication
			if errors.Is(err, util.ErrInvalidJwtToken) {
				u, err = s.authenticateByAccessKey(token)
				if err != nil {
					return nil, status.Error(codes.Unauthenticated, "Invalid credentials")
				}
			} else {
				// Other JWT errors (expired, invalid signature, etc.)
				return nil, status.Error(codes.Unauthenticated, "Login failed")
			}
		} else {
			// JWT token authentication succeeded, check single user login
			lastLoginExpireTime, err := s.getLastLoginExpireTime(ctx, u.User)
			if err == nil && lastLoginExpireTime > u.Expired {
				return nil, status.Error(codes.Unauthenticated, "Already logged")
			}
			// Update user active time (throttled to 5 minutes)
			if err := s.updateUserActiveTm(u.User); err != nil {
				return nil, status.Error(codes.Internal, "Login Failed")
			}
		}

		// 接口鉴权
		ok, err = authentication(u, args.FullMethod)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Authorization failed:%v", err)
		}
		if !ok {
			logger.Debugf("user(%s) has no permission: %s", u.User, args.FullMethod)
			return nil, status.Error(codes.PermissionDenied, "No permission")
		}

		md.Append("token", token)
		md.Append("user", u.User)
		md.Append("role", u.Role)
		md.Append("priv", strconv.Itoa(u.Priv))
		newCtx := metadata.NewIncomingContext(ctx, md)

		return handler(newCtx, req)
	}
}

// grpc logging
func (s *GrpcService) logging() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, args *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (any, error) {
		s = s.withContext(ctx)
		startTime := time.Now()
		var addr, remoteIP string
		if peerInfo, ok := peer.FromContext(ctx); ok {
			if tcpAddr, ok := peerInfo.Addr.(*net.TCPAddr); ok {
				addr = tcpAddr.IP.String()
			} else {
				addr = peerInfo.Addr.String()
			}
		}

		md, _ := metadata.FromIncomingContext(ctx) // ignore the `error` return value
		rips := md.Get("x-real-ip")
		if len(rips) > 0 {
			remoteIP = rips[0]
			addr = remoteIP
		} else {
			remoteIP = addr
		}

		var quota float64
		if deadline, ok := ctx.Deadline(); ok {
			quota = time.Until(deadline).Seconds()
		}
		// call server handler
		resp, err := handler(ctx, req)

		duration := time.Since(startTime)
		fullMethod := args.FullMethod
		argsStr := fmt.Sprintf("%v", req)
		if stringer, ok := req.(fmt.Stringer); ok {
			argsStr = stringer.String()
		}
		maskedArgsStr := eventMasking(fullMethod, argsStr)
		logFields := logger.Fields{
			"ip":      addr,
			"path":    fullMethod,
			"ts":      duration.Seconds(),
			"timeout": quota,
			"args":    maskedArgsStr,
		}
		// add audit log
		eventResult := "Success"
		if err != nil {
			logFields["error"] = err.Error()
			logFields["stack"] = fmt.Sprintf("%+v", err)
			eventResult = "Failed"
		}
		username := ""
		if len(md["user"]) > 0 {
			username = md["user"][0]
		} else if fullMethod == "/ada.ADA/Login" || fullMethod == "/ada.ADA/Logout" {
			username = getRegUser(argsStr)
		}

		if event, ok := v2.URLEventMap[args.FullMethod]; ok {
			eventArgs := eventMasking(fullMethod, argsStr)
			_ = server.AddAuditLog(s.env, username, remoteIP, event, eventArgs, eventResult)
		}
		logger.WithFields(logFields).Debugf("grpc request")
		return resp, err
	}
}

// signal handler
func (s *GrpcService) SignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	ch := <-c

	logger.Infof("apiserver get %s signal", ch.String())
	switch ch {
	case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
		logger.Info("apiserver exit")
		s.Stop()
		time.Sleep(time.Second)
		return
	case syscall.SIGHUP:
		// TODO reload
	default:
		return
	}
}

// GetUser is ADAServiceV2's internal interface
func (h *ADAServiceV2) GetUser(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx) // ignore the `error` return value
	return md["user"][0]
}

// GetUser is ADAServiceV2's internal interface
func (h *ADAServiceV2) IsSuper(ctx context.Context) bool {
	md, _ := metadata.FromIncomingContext(ctx) // ignore the `error` return valu
	switch md["priv"][0] {
	case strconv.Itoa(common.PrivSuper):
		return true
	default:
		return false
	}
}

// 鉴权
func authentication(u *util.UserClaim, fullMethod string) (bool, error) {
	if u.Priv == common.PrivSuper {
		return true, nil
	}
	return v2.CheckUserAccess(u.Role, fullMethod), nil
}

// 脱敏
func eventMasking(fullMethod string, data string) string {
	for url, mkList := range v2.URLEventMaskingMap {
		if url == fullMethod {
			for _, m := range mkList {
				reg := regexp.MustCompile(m + ":(.*)\"")
				data = reg.ReplaceAllString(data, "\""+m+"\""+`:"*""`)
			}
		}
	}
	return data
}

func getRegUser(data string) string {
	reg := regexp.MustCompile(`username:"(.*?)"`)
	return reg.FindStringSubmatch(data)[1]
}

type validator interface {
	Validate() error
}

// proto参数校验
func (s *GrpcService) validate() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if v, ok := req.(validator); ok {
			if err := v.Validate(); err != nil {
				logger.Infof("middleware validate parameter err(path:%s):%v", info.FullMethod, err)
				return nil, status.Error(codes.InvalidArgument, "Invalid argument")
			}
		}
		return handler(ctx, req)
	}
}

// get system language
func getSysLanguage(env *config.Env) string {
	sysInfo, err := server.GetSystemInfo(env)
	if err != nil {
		return bCommon.LangZh
	}

	return sysInfo.SystemLanguage
}

func (h *ADAServiceV2) I18n(m string, args ...any) string {
	// param: Key1 OR Key1.Key2 OR Key1.Key3

	var langMap map[string]any
	switch h.language {
	case bCommon.LangEn:
		langMap = v2.I18nLangEnMap
	case bCommon.LangZh:
		langMap = v2.I18nLangZhMap
	default:
		logger.Warnf("Unsupported system language for i18n: %s", h.language)
		langMap = v2.I18nLangEnMap // Default to English
	}

	parts := strings.Split(m, ".")
	currentLevel := langMap // Start at the top level

	var baseMsg string // Variable to store the retrieved base message
	found := false

	for i, part := range parts {
		if i == len(parts)-1 { // Last part, expect a string
			if msg, ok := currentLevel[part].(string); ok {
				baseMsg = msg
				found = true
			} else {
				logger.Debugf("i18n key not found or not a string at final level: %s (part: %s)", m, part)
				baseMsg = m // Use original key as fallback message
			}
			break // Found the final part (or failed)
		} else { // Intermediate part, expect a map
			if nextLevel, ok := currentLevel[part].(map[string]any); ok {
				currentLevel = nextLevel
			} else {
				logger.Debugf("i18n key not found or not a map at intermediate level: %s (part: %s)", m, part)
				baseMsg = m // Use original key as fallback message
				break       // Stop searching if intermediate path is wrong
			}
		}
	}

	if !found && baseMsg == "" { // If loop didn't set baseMsg (e.g., empty key)
		logger.Warnf("i18n lookup failed unexpectedly for key: %s", m)
		baseMsg = m
	}

	// Format the message if arguments are provided
	if len(args) > 0 {
		// Basic check to see if the message looks like a format string
		// This isn't foolproof but avoids unnecessary Sprintf calls
		if strings.Contains(baseMsg, "%") {
			return fmt.Sprintf(baseMsg, args...)
		} else {
			// Log a warning if args are provided but the base message isn't a format string
			logger.Warnf("i18n key '%s' received arguments but message '%s' doesn't contain format specifiers", m, baseMsg)
			return baseMsg // Return unformatted message
		}
	}

	return baseMsg // Return the base message if no args
}
