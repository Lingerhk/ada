package main

import (
	"ada/backend/apiserver/common"
	"ada/backend/apiserver/config"
	"ada/backend/apiserver/service"
	"ada/backend/apiserver/util"
	"ada/infra/license"
	infranet "ada/infra/net"
	_ "ada/infra/version"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
)

////go:embed /xxx/xx
//var frontend embed.FS

func main() {
	logger.Info("starting ada_apiserver for ADA")
	confPath := os.Getenv("APISERVER_CONF_PATH")
	if confPath == "" {
		confPath = "./apiserver.yaml"
	}

	logger.Infof("load configure from %s", confPath)
	env, err := config.Init(confPath)
	if err != nil {
		logger.Errorf("init apiserver config failed: %v", err)
		os.Exit(1)
	}

	go httpServe(env) // 启动http server,处理静态文件和本地curl请求(license相关操作)

	s := service.New(env)

	go s.SignalHandler()

	if err := s.Start(env.Cfg.BindSrv.GrpcAddr); err != nil {
		logger.Errorf("start apiserver grpc service failed: %v", err)
		os.Exit(1)
	}
}

func httpServe(env *config.Env) {
	h := gin.Default()
	h.Use(gin.Recovery())

	// handle license
	hh := httpHandle{env}
	h.GET("/lic/trait", hh.licenseHandler)
	h.GET("/lic/info", hh.licenseHandler)
	h.POST("/lic/update", hh.licenseHandler)

	// handle health check
	h.GET("/ping", hh.pingHandler)

	// handle static file
	//h.StaticFS("/static", http.FS(frontend)) // http.FileServer(http.FS(frontend))) // TODO: 等前端打包好后开启次route path

	// handle webssh
	wss := util.NewWebSshStream(env.RedisCli)
	h.GET("/webssh/stream", wss.Stream)

	// handle kibana proxy
	h.Any("/kibana/*proxyPath", hh.kibanaProxyHandler)

	logger.Infof("starting http service at:%s", env.Cfg.BindSrv.HttpAddr)
	if err := h.Run(env.Cfg.BindSrv.HttpAddr); err != nil {
		logger.Errorf("start web serive err: %v", err)
	}
}

type httpHandle struct {
	env *config.Env
}

func (h *httpHandle) pingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "pong"})
}

func (h *httpHandle) genSession(c *gin.Context) {
	// Get JWT token from cookie
	token, err := c.Cookie("token")
	if err != nil || token == "" {
		logger.Errorf("gen session failed: missing token cookie, err: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"code": 1, "error": "unauthorized: missing token"})
		return
	}

	// Parse and validate token
	claim, err := util.ParseToken(token, common.JWT_SECRET)
	if err != nil {
		logger.Errorf("gen session failed: invalid token, err: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"code": 2, "error": "unauthorized: invalid token"})
		return
	}

	// Log the authenticated user
	logger.Debugf("user %s (role: %s) requesting kibana session", claim.User, claim.Role)

	// Use infra HTTP client with TLS skip verification for Kibana
	client := infranet.NewHTTPClient(60)
	userParams := map[string]any{
		"username": h.env.Cfg.Kibana.Username,
		"password": h.env.Cfg.Kibana.Password,
	}
	params := map[string]any{
		"providerType": "basic",
		"providerName": "basic",
		"currentURL":   fmt.Sprintf("%s/login?next=%s/", h.env.Cfg.Kibana.Address, h.env.Cfg.Kibana.Address),
		"params":       userParams,
	}

	data, _ := json.Marshal(params)
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/internal/security/login", h.env.Cfg.Kibana.Address), bytes.NewBuffer(data))
	if err != nil {
		logger.Errorf("gen session failed: create request error, err: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"code": 3, "error": "failed to create kibana session request"})
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Origin", h.env.Cfg.Kibana.Address)
	req.Header.Set("Referer", h.env.Cfg.Kibana.Address)
	req.Header.Set("kbn-version", "8.18.8")

	res, err := client.Do(req)
	if err != nil || (res != nil && res.StatusCode != 200 && res.StatusCode != 204) {
		if res != nil {
			logger.Errorf("gen session failed, err: %v, status code: %d", err, res.StatusCode)
			body, _ := io.ReadAll(res.Body)
			logger.Errorf("gen session failed, response: %s", string(body))
		} else {
			logger.Errorf("gen session failed, err: %v", err)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"code": 4, "error": "failed to generate kibana session"})
		return
	}

	cookies := res.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "sid" {
			sessionKey := fmt.Sprintf("ada:server:kibana_session:%s", claim.User)
			err := h.env.RedisCli.Set(c, sessionKey, cookie.Value, time.Duration(common.LoginExpired)*time.Second).Err()
			if err != nil {
				logger.Errorf("failed to store kibana session in redis: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store session"})
				return
			}

			logger.Infof("kibana session created successfully for user %s", claim.User)
			c.JSON(http.StatusOK, gin.H{"code": 0, "error": ""})
			return
		}
	}
	logger.Errorf("gen session failed, no sid cookie")
	c.JSON(http.StatusInternalServerError, gin.H{"error": "gen session failed, no sid cookie"})
}

func (h *httpHandle) kibanaProxyHandler(c *gin.Context) {
	path := c.Param("proxyPath")

	// Handle session generation endpoint
	if path == "/GenSession" {
		h.genSession(c)
		return
	}

	// Get authenticated user from token cookie
	token, err := c.Cookie("token")
	if err != nil || token == "" {
		logger.Errorf("kibana proxy: missing token cookie, err: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized: missing token"})
		return
	}

	claim, err := util.ParseToken(token, common.JWT_SECRET)
	if err != nil {
		logger.Errorf("kibana proxy: invalid token, err: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized: invalid token"})
		return
	}

	targetURL, err := url.Parse(h.env.Cfg.Kibana.Address)
	if err != nil {
		logger.Errorf("failed to parse kibana address: %v", err)
		c.String(http.StatusInternalServerError, "Kibana proxy configuration error")
		return
	}

	// Get Kibana session ID from Redis using authenticated user

	sessionKey := fmt.Sprintf("ada:server:kibana_session:%s", claim.User)
	sid, err := h.env.RedisCli.Get(c, sessionKey).Result()
	if err == redis.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "kibana session not found or expired"})
		return
	}
	if err != nil {
		logger.Errorf("get kibana sid failed for user %s, err: %v", claim.User, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "kibana session not found or expired"})
		return
	}

	// Create reverse proxy with manual location handling
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			// Reconstruct full path with /kibana prefix since Kibana has server.basePath="/kibana"
			req.URL.Path = "/kibana" + path
			req.URL.RawQuery = c.Request.URL.RawQuery
			req.Host = targetURL.Host
			req.Header.Set("Cookie", "sid="+sid)
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		ModifyResponse: func(resp *http.Response) error {
			// Clear Set-Cookie header (we manage sessions via Redis)
			resp.Header.Del("Set-Cookie")
			// Location header is already correct from Kibana, no need to modify
			return nil
		},
	}

	// Forward the request
	proxy.ServeHTTP(c.Writer, c.Request)
}

func (h *httpHandle) licenseHandler(c *gin.Context) {
	switch c.Request.RequestURI {
	case "/lic/trait":
		trait := license.GetTrait()
		var buf bytes.Buffer
		util.GenerateQR(trait, &buf)
		c.String(http.StatusOK, "trait: %s\n%s", trait, buf.String())
		return
	case "/lic/info":
		licer, err := license.NewAdaLicense(h.env.RedisCli)
		if err != nil {
			logger.Errorf("new license client err:%v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
			return
		}
		info := licer.GetInfo()
		c.JSON(http.StatusOK, gin.H{"sn": info.SnId, "trait": info.Trait, "count": info.Count, "end": time.Unix(info.EndTm, 0).String()})
		return
	case "/lic/update":
		licer, err := license.NewAdaLicense(h.env.RedisCli)
		if err != nil {
			logger.Errorf("new license client err:%v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
			return
		}

		cnt, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
			return
		}
		if len(string(cnt)) != 336 {
			c.JSON(http.StatusBadRequest, gin.H{"err": "Invalid license content(length must be 336)"})
			return
		}

		if err := licer.UpdateCnt(string(cnt)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"err": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"msg": "ok"})
	}
}
