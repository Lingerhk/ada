package worker

import (
	"ada/infra/license"
	"ada/infra/mongo"
	"ada/scanner/common"
	"ada/scanner/config"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

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
	randKey   string
	svcStop   bool
	mu        sync.RWMutex // 读写锁，用于保护pending
	pending   bool
}

func New(env *config.Env) (*ScanSvc, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// 1.生成随机数
	b := make([]byte, 16)
	n, _ := rand.Read(b)
	randKey := base64.StdEncoding.EncodeToString(b[:n])
	err := env.RedisCli.Set(ctx, common.ScannerRedisRandKey, randKey, 30*time.Second).Err()
	if err != nil {
		cancel()
		return nil, err
	}

	return &ScanSvc{ctx: ctx, cfg: env.Cfg, redisCli: env.RedisCli, mongoCli: env.MongoCli, cancel: cancel, randKey: randKey}, nil
}

func (s *ScanSvc) Setup() error {
	for {
		time.Sleep(10 * time.Second)
		// 1.再次执行runtime check
		if s.expired() {
			return errors.New("setup scanner failed")
		}
		if !s.pending {
			break
		}
	}

	// 2.将enc.tar.gz 文件随机写入tmp
	tmpDir, err := os.MkdirTemp(os.TempDir(), "systemd-private-*")
	if err != nil {
		logger.Errorf("create tmp dir err:%v", err)
		return err
	}
	defer os.RemoveAll(tmpDir)

	scFile := filepath.Join(tmpDir, "sc_enc.tar.gz")
	venvFile := filepath.Join(tmpDir, "venv_enc.tar.gz")
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
	s.svcStop = true
}

// RuntimeCheck 进行运行时检测，防止在非ada环境执行
func (s *ScanSvc) RuntimeCheck() {
	defer s.clean()

	checkTicker := time.NewTicker(5 * time.Second)
	defer checkTicker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-checkTicker.C:
			{
				if s.expired() {
					s.Stop()
					return
				}
			}
		}
	}
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

// 执行具体的runtime check逻辑
// 1.check机器指纹是否变化
// 2.check redis中在Setup阶段初始化的随机数是否正确
func (s *ScanSvc) expired() bool {
	defer s.mu.Unlock()

	lic, err := license.NewAdaLicense(s.redisCli)
	if err != nil {
		logger.Warnf("init license err:%v", err)
		s.mu.Lock()
		s.pending = true
		return false
	}

	k, err := s.redisCli.Get(s.ctx, common.ScannerRedisRandKey).Result()
	if err != nil {
		//logger.Errorf("redis get rand key err:%v", err)
		s.mu.Lock()
		s.pending = true
		return false
	}

	if k != s.randKey {
		s.mu.Lock()
		s.pending = true
		return false
	}

	err = s.redisCli.Set(s.ctx, "ada:rand_key", k, 30*time.Second).Err()
	if err != nil {
		logger.Errorf("redis set rand key err:%v", err)
		s.mu.Lock()
		s.pending = true
		return false
	}

	if !lic.Expired() {
		s.mu.Lock()
		s.pending = false
	} else {
		s.mu.Lock()
		s.pending = true
	}

	if lic.DelayExpired() {
		return true
	}

	return false
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
