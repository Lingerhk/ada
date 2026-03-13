package server

import (
	"ada/backend/apiserver/common"
	"ada/backend/tasker/api"
	"ada/backend/tasker/config"
	"ada/backend/tasker/tasks"
	"ada/backend/tasker/worker"
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/RichardKnop/machinery/v2"
	redisbackend "github.com/RichardKnop/machinery/v2/backends/redis"
	redisbroker "github.com/RichardKnop/machinery/v2/brokers/redis"
	mconfig "github.com/RichardKnop/machinery/v2/config"
	eagerlock "github.com/RichardKnop/machinery/v2/locks/eager"
	"github.com/golang-jwt/jwt"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const (
	_abortIndex int8 = math.MaxInt8 / 2
	_headerAuth      = "authorization"
	_bearer          = "Bearer"
)

var rpcHandlers []grpc.UnaryServerInterceptor

type TaskService struct {
	taskServer   *TaskServer
	grpcServer   *grpc.Server
	httpServer   *http.Server
	cronServer   *CronScheduler
	pubsubServer *PubsubServer
	syslogServer *SyslogServer
}

type TaskServer struct {
	env     *config.Env
	taskSrv *machinery.Server
}

func NewTaskServer(env *config.Env, ts *machinery.Server) *TaskServer {
	return &TaskServer{
		env:     env,
		taskSrv: ts,
	}
}

func MachineryServer(env *config.Env, taskQueue string) (*machinery.Server, error) {
	cnf := &mconfig.Config{
		DefaultQueue:    taskQueue,
		ResultsExpireIn: 12 * 3600,
		NoUnixSignals:   true,
		Redis: &mconfig.RedisConfig{
			MaxIdle:                3,
			IdleTimeout:            240,
			ReadTimeout:            15,
			WriteTimeout:           15,
			ConnectTimeout:         15,
			NormalTasksPollPeriod:  1000,
			DelayedTasksPollPeriod: 500,
		},
	}

	broker := redisbroker.NewGR(cnf, []string{env.Cfg.Redis.AddrTmp}, 0)
	backend := redisbackend.NewGR(cnf, []string{env.Cfg.Redis.AddrTmp}, 0)
	lock := eagerlock.New()

	server := machinery.NewServer(cnf, broker, backend, lock)

	w := worker.New(env)
	err := server.RegisterTasks(tasks.GetTaskMap(w))
	if err != nil {
		return nil, err
	}
	return server, err
}

func New(env *config.Env) (*TaskService, error) {
	taskSrv, err := MachineryServer(env, "ada:tasker:task_queue")
	if err != nil {
		return nil, err
	}

	taskServer := NewTaskServer(env, taskSrv)

	// grpc server
	gprcServer := grpc.NewServer(grpc.UnaryInterceptor(rpcInterceptor))
	rpcUse(rpcAuthMiddleware())
	api.RegisterADATaskServer(gprcServer, taskServer)

	// http server
	httpServer := &http.Server{
		Addr:         env.Cfg.TaskSrv.HttpAddr,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      RegisterHTTPMux(taskServer),
	}

	// pubsub server
	pubsubServer := NewPubsubServer(env)

	// cron server
	cronServer, err := NewCronScheduler(taskServer)
	if err != nil {
		return nil, err
	}

	// syslog server
	syslogServer, err := NewSyslogServer(env)
	if err != nil {
		return nil, err
	}

	return &TaskService{
		taskServer:   taskServer,
		grpcServer:   gprcServer,
		httpServer:   httpServer,
		cronServer:   cronServer,
		pubsubServer: pubsubServer,
		syslogServer: syslogServer,
	}, nil
}

func (s *TaskService) Start() error {
	logger.Info("starting cron scheduler")
	go s.cronServer.CronTaskServe()

	logger.Info("starting pubsub handler")
	go s.pubsubServer.EventsServe()

	logger.Infof("starting syslog/pktlog service at %s", s.taskServer.env.Cfg.TaskSrv.SyslogAddr)
	go s.syslogServer.SyslogServe()
	go s.syslogServer.PktlogServe()

	logger.Infof("starting http service at %s", s.taskServer.env.Cfg.TaskSrv.HttpAddr)
	go s.httpServer.ListenAndServe()

	logger.Infof("starting grpc service at %s", s.taskServer.env.Cfg.TaskSrv.GrpcAddr)
	listener, err := net.Listen("tcp", s.taskServer.env.Cfg.TaskSrv.GrpcAddr)
	if err != nil {
		return err
	}

	reflection.Register(s.grpcServer)
	err = s.grpcServer.Serve(listener)
	if err != nil {
		return err
	}

	return nil
}

func (s *TaskService) Stop() {
	s.syslogServer.Stop()
	s.pubsubServer.Stop()
	s.grpcServer.Stop()
	s.httpServer.Shutdown(nil)
	s.cronServer.Stop()
}

// signal handler
func (s *TaskService) SignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	ch := <-c

	logger.Infof("tasker(server) get %s signal", ch.String())
	switch ch {
	case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
		logger.Info("tasker(server) exit")
		s.Stop()
		time.Sleep(time.Second)
		return
	case syscall.SIGHUP:
		// TODO reload
	default:
		return
	}
}

// Execution is done in left-to-right order, including passing of context.
// For example ChainUnaryServer(one, two, three) will execute one before two before three, and three
// will see context changes of one and two.
func rpcInterceptor(ctx context.Context, req any,
	args *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	var (
		i     int
		chain grpc.UnaryHandler
	)

	n := len(rpcHandlers)
	if n == 0 {
		return handler(ctx, req)
	}

	chain = func(ic context.Context, ir any) (any, error) {
		if i == n-1 {
			return handler(ic, ir)
		}
		i++
		return rpcHandlers[i](ic, ir, args, chain)
	}

	return rpcHandlers[0](ctx, req, args, chain)
}

// Use attachs a global inteceptor to the server.
// For example, this is the right place for a rate limiter or error management inteceptor
func rpcUse(handlers ...grpc.UnaryServerInterceptor) {
	finalSize := len(rpcHandlers) + len(handlers)
	if finalSize >= int(_abortIndex) {
		remaining := int(_abortIndex) - len(rpcHandlers)
		if remaining <= 0 {
			logger.Errorf("task grpc service: interceptor limit reached (%d), ignoring %d handlers", _abortIndex, len(handlers))
			return
		}

		logger.Errorf("task grpc service: interceptor limit reached (%d), truncating %d handlers to %d", _abortIndex, len(handlers), remaining)
		handlers = handlers[:remaining]
		finalSize = len(rpcHandlers) + len(handlers)
	}
	mergedHandlers := make([]grpc.UnaryServerInterceptor, finalSize)
	copy(mergedHandlers, rpcHandlers)
	copy(mergedHandlers[len(rpcHandlers):], handlers)
	rpcHandlers = mergedHandlers
}

// rpc auth middleware
func rpcAuthMiddleware() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, args *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (resp any, err error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument, "空数据")
		}
		// 获取 header 的`authorization: Bearer token`字段的值
		var token string
		if val, ok := md[_headerAuth]; ok {
			splits := strings.SplitN(val[0], " ", 2)
			if len(splits) < 2 || splits[0] != _bearer {
				return nil, status.Errorf(codes.Unauthenticated, "授权失败")
			}
			token = splits[1]
		}
		// 解析jwt-token进行认证
		u, err := parseToken(token, common.JWT_SECRET)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "登录过期，请重新登录")
		}

		md.Append("token", token)
		md.Append("user", u.User)
		md.Append("role", u.Role)
		md.Append("priv", strconv.Itoa(u.Priv))
		newCtx := metadata.NewIncomingContext(ctx, md)

		return handler(newCtx, req)
	}
}

// 处理err可参考: https://godoc.org/github.com/dgrijalva/jwt-go#ex-Parse--ErrorChecking
// 或jwt.MapClaims的Valid()
type UserClaim struct {
	User    string `json:"user"`
	Role    string `json:"role"`
	Priv    int    `json:"priv"`
	Expired int64  `json:"exp"`
}

func (c UserClaim) Valid() error {
	vErr := new(jwt.ValidationError)
	now := time.Now().Unix()
	if c.Expired == 0 {
		vErr.Inner = fmt.Errorf("exp is required")
		vErr.Errors |= jwt.ValidationErrorClaimsInvalid
	}
	if c.Expired < now {
		delta := time.Unix(now, 0).Sub(time.Unix(c.Expired, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if c.User == "" {
		vErr.Inner = fmt.Errorf("user is required")
		vErr.Errors |= jwt.ValidationErrorClaimsInvalid
	}

	if c.Role == "" {
		vErr.Inner = fmt.Errorf("role is required")
		vErr.Errors |= jwt.ValidationErrorClaimsInvalid
	}

	if c.Priv == 0 {
		vErr.Inner = fmt.Errorf("priv is required")
		vErr.Errors |= jwt.ValidationErrorClaimsInvalid
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

// 解析token获取user消息
func parseToken(tokenStr, authSecret string) (*UserClaim, error) {
	fn := func(token *jwt.Token) (any, error) {
		return []byte(authSecret), nil
	}

	token, err := jwt.ParseWithClaims(tokenStr, &UserClaim{}, fn)
	if err != nil {
		return nil, err
	}

	claim, ok := token.Claims.(*UserClaim)
	if !ok {
		return nil, fmt.Errorf("cannot convert claim to BasicClaim")
	}

	return claim, nil
}
