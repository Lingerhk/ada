package main

import (
	"ada/backend/apiserver/config"
	"ada/backend/apiserver/service"
	"ada/backend/apiserver/util"
	"ada/infra/license"
	_ "ada/infra/version"
	"bytes"
	"github.com/gin-gonic/gin"
	logger "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os"
	"time"
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
		panic(err)
	}

	go httpServe(env) // 启动http server,处理静态文件和本地curl请求(license相关操作)

	s := service.New(env)

	go s.SignalHandler()

	if err := s.Start(env.Cfg.BindSrv.GrpcAddr); err != nil {
		logger.Panic(err)
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

	// handle static file
	//h.StaticFS("/static", http.FS(frontend)) // http.FileServer(http.FS(frontend))) // TODO: 等前端打包好后开启次route path

	// handle webssh
	wss := util.NewWebSshStream(env.RedisCli)
	h.GET("/webssh/stream", wss.Stream)

	logger.Infof("starting http service at:%s", env.Cfg.BindSrv.HttpAddr)
	if err := h.Run(env.Cfg.BindSrv.HttpAddr); err != nil {
		logger.Errorf("start web serive err: %v", err)
	}
}

type httpHandle struct {
	env *config.Env
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

		cnt, err := ioutil.ReadAll(c.Request.Body)
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
