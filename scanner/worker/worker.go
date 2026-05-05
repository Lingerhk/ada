package worker

import (
	"ada/infra/mongo"
	"ada/scanner/common"
	"ada/scanner/config"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"ada/scanner/scgo"

	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
)

//go:embed sc_enc.tar.gz
var scCnt []byte

//go:embed venv_enc.tar.gz
var venvCnt []byte

type ScanSvc struct {
	ctx       context.Context
	cfg       *config.Config
	redisCli  *redis.Client
	mongoCli  mongo.DBAdaptor
	cancel    context.CancelFunc
	pyRunPath string
}

func New(env *config.Env) (*ScanSvc, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &ScanSvc{ctx: ctx, cfg: env.Cfg, redisCli: env.RedisCli, mongoCli: env.MongoCli, cancel: cancel}, nil
}

func (s *ScanSvc) Setup() error {
	// 2.将enc.tar.gz 文件随机写入tmp
	tmpDir, err := os.MkdirTemp(os.TempDir(), "systemd-private-*")
	if err != nil {
		logger.Errorf("create tmp dir err:%v", err)
		return err
	}
	defer os.RemoveAll(tmpDir)

	scFile := filepath.Join(tmpDir, "sc_enc.tar.gz")
	venvFile := filepath.Join(tmpDir, "venv_enc.tar.gz")
	if len(scCnt) < 1024 {
		return errors.New("embedded scanner package sc_enc.tar.gz is not bundled")
	}
	if err := os.WriteFile(scFile, scCnt, 0644); err != nil {
		logger.Errorf("write enc file err:%v", err)
		return err
	}

	// TODO: 随机生成多个目录，并检测是否被读/打开

	// 2.执行解压(解压密钥由不同环境存在差异,在部署的时候生成key)
	if len(venvCnt) > 1024 {
		if err := os.WriteFile(venvFile, venvCnt, 0644); err != nil {
			logger.Errorf("write enc file err:%v", err)
			return err
		}

		if err := s.tar(venvFile); err != nil {
			logger.Errorf("tar enc file err:%v", err)
			return err
		}
	}
	if err := s.tar(scFile); err != nil {
		logger.Errorf("tar enc file err:%v", err)
		return err
	}

	// 3.部署.so文件到指定位置

	// 4.更新 s.pyRunPath
	//s.pyRunPath = filepath.Join(common.GetCurrentPath(), "sc")
	s.pyRunPath = common.ScannerRunPath //filepath.Join("", "sc")

	return nil
}

func (s *ScanSvc) Stop() {
	defer s.clean()

	s.cancel()
}

func (s *ScanSvc) Worker() {
	defer s.clean()

	// Default implementation: Go celery worker + Python plugin runtime (.so)
	env := &config.Env{Cfg: s.cfg, RedisCli: s.redisCli, MongoCli: s.mongoCli}
	svc, err := scgo.NewService(env, s.pyRunPath)
	if err != nil {
		logger.Errorf("init scgo service err:%v", err)
		s.Stop()
		return
	}

	if err := svc.Start(s.ctx); err != nil {
		logger.Errorf("scgo service stopped with err:%v", err)
		s.Stop()
		return
	}
}

// 执行清理工作
func (s *ScanSvc) clean() {
	logger.Debug("start clean()...")
	os.RemoveAll(filepath.Join(s.pyRunPath, ".sc"))
	os.RemoveAll(filepath.Join(s.pyRunPath, ".venv"))
	//os.RemoveAll("/var/log/scada/sc.log")
	//os.RemoveAll("/var/log/scada/plugin.log")
}

func (s *ScanSvc) tar(pkgFile string) error {
	cmdStr := fmt.Sprintf("/usr/bin/openssl des3 -d -k %s -salt -in %s | tar -C %s -xzf -",
		common.ScannerPkgDecryptKey, pkgFile, common.ScannerRunPath)
	c := exec.Command("/bin/bash", "-c", cmdStr)
	_, err := c.CombinedOutput()
	if err != nil {
		logger.Errorf("decrypt pkg err:%v", err)
		return err
	}

	return nil
}
