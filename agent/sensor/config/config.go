package config

import (
	"ada/agent/sensor/common"
	"ada/infra/crypto"
	logrusredis "ada/infra/loghook"
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/natefinch/lumberjack"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const (
	cfgEncKey   = "adcc368715ce1bd2"
	confFile    = "sensor.yaml"
	confEncFile = "sensor.cfg"
)

var cfgEncrypted bool

type LogCfg struct {
	LogPath  string `yaml:"LogPath"`
	LogLevel string `yaml:"LogLevel"`
	IsStdOut bool   `yaml:"IsStdOut"`
}

type RedisCfg struct {
	Password string `yaml:"Password"`
	Port     int    `yaml:"Port"`
}

type SensorCfg struct {
	RegHost string `yaml:"RegHost"`
	RegCode string `yaml:"RegCode"`
}

type Config struct {
	ProjectName string    `yaml:"ProjectName"`
	Log         LogCfg    `yaml:"Log"`
	Redis       RedisCfg  `yaml:"Redis"`
	Sensor      SensorCfg `yaml:"Sensor"`
}

type Env struct {
	Cfg      *Config
	SensorId string
	RedisCli *redis.Client
}

//go:embed client.crt client.key ca.crt
var certFiles embed.FS

var (
	clientCrt []byte
	clientKey []byte
	caCrt     []byte
)

func init() {
	var err error

	clientCrt, err = certFiles.ReadFile("client.crt")
	if err != nil {
		logger.Fatalf("Failed to read client.crt: %v", err)
	}

	clientKey, err = certFiles.ReadFile("client.key")
	if err != nil {
		logger.Fatalf("Failed to read client.key: %v", err)
	}

	caCrt, err = certFiles.ReadFile("ca.crt")
	if err != nil {
		logger.Fatalf("Failed to read ca.crt: %v", err)
	}
}

func InitLog(setting *Config, redisCli *redis.Client) error {
	logger.SetFormatter(&logger.JSONFormatter{})
	if setting.Log.LogLevel == "" {
		return nil
	}

	lvl, err := logger.ParseLevel(setting.Log.LogLevel)
	if err != nil {
		return err
	}
	logger.SetLevel(lvl)

	if setting.Log.IsStdOut {
		logger.SetOutput(os.Stdout)
		logger.SetFormatter(&logger.TextFormatter{})
	} else if setting.Log.LogPath != "" {
		logFile := path.Join(common.GetCurrentPath(), setting.Log.LogPath, setting.ProjectName+".log")
		if err == nil {
			logout := &lumberjack.Logger{
				Filename:   logFile,
				MaxSize:    20,    // 日志文件最大size, 单位是MB
				MaxBackups: 2,     // 最大过期日志保留的个数
				MaxAge:     60,    // 保留过期文件的最大时间间隔，单位是天
				Compress:   false, // 是否需要压缩滚动日志，使用的gzip压缩
			}
			logger.SetOutput(logout)
		}
	}

	logger.SetReportCaller(true)

	hook := logrusredis.NewLogrusRedis(redisCli, "ada:logs_queue:sensor")
	logger.AddHook(hook)

	return nil
}

func InitRedisClient(setting *Config) (*redis.Client, error) {
	// Load client certificate and private key
	clientCert, err := tls.X509KeyPair(clientCrt, clientKey)
	if err != nil {
		logger.Errorf("loading client cert and key:%v", err)
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCrt)
	tlsConfig := &tls.Config{
		RootCAs:            pool,
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{clientCert},
		MinVersion:         tls.VersionTLS12,
	}

	redisPort := setting.Redis.Port
	if redisPort == 0 {
		redisPort = 9091 // 默认为9091/tcp端口
	}

	opt := redis.Options{
		Addr:         fmt.Sprintf("%s:%d", setting.Sensor.RegHost, redisPort),
		Password:     setting.Redis.Password,
		DB:           0,
		DialTimeout:  15 * time.Second,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		PoolSize:     3,
		TLSConfig:    tlsConfig,
	}

	rdb := redis.NewClient(&opt)
	err = rdb.Ping(context.Background()).Err()
	if err != nil {
		return nil, err
	}

	return rdb, err
}

func LoadConfig() ([]byte, error) {
	var fileCnt, fileEncCnt []byte
	var err error
	var cfgFileFound bool

	confFilePath := filepath.Join(common.SensorDir, confFile)
	confEncFilePath := filepath.Join(common.SensorDir, confEncFile)

	_, err = os.Stat(confFilePath)
	if err == nil {
		cfgFileFound = true
		cfgEncrypted = false
		fileCnt, err = os.ReadFile(confFilePath)
		if err != nil {
			return nil, err
		}
	}

	_, err = os.Stat(confEncFilePath)
	if err == nil {
		cfgFileFound = true
		cfgEncrypted = true
		fileCntTmp, err := os.ReadFile(confEncFilePath)
		if err != nil {
			return nil, err
		}
		fileEncCnt, err = base64.StdEncoding.DecodeString(string(fileCntTmp))
		if err != nil {
			return nil, err
		}
	}

	if !cfgFileFound {
		return nil, fmt.Errorf("config file(%s|%s) not found", confFile, confEncFile)
	}

	if cfgEncrypted {
		aes := crypto.NewAes([]byte(cfgEncKey))
		fileCnt, err = aes.Decrypt(fileEncCnt)
		if err != nil {
			return nil, err
		}
		logger.Infof("load configure from %s", confEncFile)
	} else {
		logger.Infof("load configure from %s", confFile)
	}

	return fileCnt, err
}

func WriteConfigFile(setting *Config) error {
	cfgBytes, err := yaml.Marshal(&setting)
	if err != nil {
		return err
	}

	var fileCnt = cfgBytes
	if cfgEncrypted {
		aes := crypto.NewAes([]byte(cfgEncKey))
		fileCnt, err = aes.Encrypt(string(cfgBytes))
		if err != nil {
			return err
		}
		fileEncCntB64 := base64.StdEncoding.EncodeToString(fileCnt)
		return os.WriteFile(confEncFile, []byte(fileEncCntB64), 0644)
	}

	return os.WriteFile(confFile, cfgBytes, 0644)
}

func readSensorId() (string, error) {
	cnt, err := os.ReadFile(filepath.Join(common.SensorDir, "uuid"))
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(string(cnt), "\n", ""), nil
}

func Init() (*Env, error) {
	content, err := LoadConfig()
	if err != nil {
		return nil, err
	}

	var setting Config
	err = yaml.Unmarshal(content, &setting)
	if err != nil {
		panic(err)
	}

	// init redis first!(before log init)
	redisCli, err := InitRedisClient(&setting)
	if err != nil {
		return nil, err
	}

	err = InitLog(&setting, redisCli)
	if err != nil {
		return nil, err
	}

	uuid, _ := readSensorId()
	return &Env{&setting, uuid, redisCli}, nil
}
