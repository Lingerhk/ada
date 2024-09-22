package config

import (
	"ada/agent/sensor/common"
	"ada/infra/crypto"
	logrusredis "ada/infra/loghook"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/natefinch/lumberjack"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
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
	clientCrt := []byte("-----BEGIN CERTIFICATE-----\nMIIEUDCCAjigAwIBAgIUFHOve8Br2ktS4w8GSDE9IugMofYwDQYJKoZIhvcNAQEL\nBQAwNTETMBEGA1UECgwKUmVkaXMgVGVzdDEeMBwGA1UEAwwVQ2VydGlmaWNhdGUg\nQXV0aG9yaXR5MB4XDTI0MDEyMTA3MjY0OVoXDTI1MDEyMDA3MjY0OVowKzETMBEG\nA1UECgwKUmVkaXMgVGVzdDEUMBIGA1UEAwwLQ2xpZW50LW9ubHkwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCUB9aLHaL893J2bKtVKcdwElqd4jMjcgbo\nzC7o5pY2FOx1JnCM8f3qtwCZqap4VzZ4fjBrAqs+COThtlaySaFyDraQ6AyNblO8\n+D6Wy1ScWKxzyVhi7i2ri4n+RCRpYmMOGE+m4is9YChXOm5BlGD8xX8SB/uEScoh\n+jTISp4Td1uTRiR8EgKQCkSCWyQqds+lUKD1zEYMl4o+s6QmI5ofeu5/3QpysHrd\nmPOVoLUosGeRf6c01lv/wG35A75Du6L+y8PULiOSJWVEAX/nwP0jroFYKsFjknyf\n+4OEuGpuG+DC/wXsY/uzpyOOHYS6ZH/FkPitVFq4hhZWhwtKS/ZhAgMBAAGjYjBg\nMAsGA1UdDwQEAwIFoDARBglghkgBhvhCAQEEBAMCB4AwHQYDVR0OBBYEFGx7NVVR\nDWAXFUyHUC4SRa6K2QaXMB8GA1UdIwQYMBaAFDIsZ1L6x4ksBjNaLRKeQC9xXXd7\nMA0GCSqGSIb3DQEBCwUAA4ICAQDaontecGGs8AQLs4BvJ7HQfSOvBF6n5iMKdZAS\nZIa+jwXSuH7sIhFvy2ttMaWuBANQj4FkOY5zCTgarZteHM7n7iKgfpO2UdXewDSo\nHfFAnIVAeuQFC2sWEfJ03quwjAXK2fi++SZzlZKe+i+72s9xB+FiwZuzGYYOjr0E\nSSTXYFWW3nD9tzlcHv+7mISaaho9udXjIbPRmgujYiEadbJvKa7GCZxQJASAO7V/\n9wfAr4s8dqdl4VE7nQMWdBeq3X3+jkQa+Ixqov7UR5lXItNPHCzjGt6KJavkiX7C\nNSThQ50NSR/3fpNLHdqiLLeTb8GViVHytoMIWDAa+tWSjFMRSKmY7Ssd8jTcOnTv\nBxVNLRfBQympBUkm/XfVZTL9UfOaSYyhGEGOQrVS+IANj1GZOq1VQt0Moo3b4dlI\n/UQCrnbQSKAtE14gpUHM72Tlek5Up72GZ1oRBceHbksSfW1IVX+IhFccJr/K2tXk\nZmnJCDI5C0fdfH7UZPcdhIBpFIGHQfZwIWY6vS2JlGGaRLzYmEUYahOuPhSvPGKm\naAS7J4bErlKSH78/FTnyuP33WWBHyqw30NZ7Pjtv6x9hUfqfGYZq8sdPaUa6ETOh\nfSnlhooCoc3ClO9dA8NAfv/WUOmxM2Rq9KhVr2Uh2/bg9RUGcL8fugobAPD2trIn\nf/fcMA==\n-----END CERTIFICATE-----")
	clientKey := []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCUB9aLHaL893J2\nbKtVKcdwElqd4jMjcgbozC7o5pY2FOx1JnCM8f3qtwCZqap4VzZ4fjBrAqs+COTh\ntlaySaFyDraQ6AyNblO8+D6Wy1ScWKxzyVhi7i2ri4n+RCRpYmMOGE+m4is9YChX\nOm5BlGD8xX8SB/uEScoh+jTISp4Td1uTRiR8EgKQCkSCWyQqds+lUKD1zEYMl4o+\ns6QmI5ofeu5/3QpysHrdmPOVoLUosGeRf6c01lv/wG35A75Du6L+y8PULiOSJWVE\nAX/nwP0jroFYKsFjknyf+4OEuGpuG+DC/wXsY/uzpyOOHYS6ZH/FkPitVFq4hhZW\nhwtKS/ZhAgMBAAECggEADg0PaY2S3MGtKP4IJlGMp3/qf42KzpzCeKL2+e73R6Nl\nTXpsWQiYUkj0IuHWt00J89aAiIvMjtsfxKf+4zX3f+DTJf6MwHj+NFP49u3Odne5\nSNVOETfr+FpKqyqzLRikb+BRYTUbJxyDP8JhWFK6AQxLEz5UOrqZV+/Mxk1E43J+\nNm7wSDUVMRr/2SCaXcQd8Lvvz6Cx+TIE6aG8LfSWsi/JmJXUF/odogPKHaIIYklL\nhf7SFQ++s9xptliPFm/vs5d4L6HziUyXz629F3Fy6ySg/M8JspmMPSM6ugaXj9jm\n/+aRcQLaLNduzlSXnRHaCjL/TbbrynIAvlBywDCSpQKBgQDAMyQf8F58PMoVTTTo\ncTAYuUcQCylKG0qbiwy1r4k+YhephK/CqfxEKehtU/vvZ70EKJdxBRjLxfA6RhWC\nKd1/SE5ZDbprnTZA+CoP4QEvGdL0sS22ot62ByKNVlet0sfZjntqoFwq8ljUH0n3\nc9hpLxdYQ7nVnI25pYU1+tZM/QKBgQDFK0Qiemw4wU4y4rO/PhYtRdEaVSuQwT6w\nboJ3wDQhC3xcZFXMTajMsp9uMhT0KSRJEgpVkffysxsWHCBEzhLuvO78oEb/1GsU\nHLL/A4xG9iyn4zl5bU6EI2Y5N/FqVb2chm+SYlqgm9+IHrzBcKsXmq5yI1OIEUTI\n82toVSf+NQKBgCwIC1Cd2qePraQvqd1OgPxJBfSw+eaWVgNIWcMN0d1Oz6jwUuu/\n0aE0EKFrSh5Qn8biHb+wsTuNvzk6cRb+zFWqlPhl4r1gqNs9fzVgEMtfmSqhpJ1g\ntrDw9YN3smKKFWrL744/6p2UI7GE8YcVLRD7ztdTvLEpSnaratcw/gNpAoGAFkfz\nZSoMfMVrftibk2sCuo7/OEiTqcIMwYdbewjfWzSfExnLkFDeWHN/DMbgE09q6E7/\nl/fs2yJeVztKcjwPa6cyIp5CJ7rrdtRfbe4KtiIvnbFR12UA0HHnpWOrBmc2DDAs\n/4/ZyfiTZCCFGB8RVpOGTyOq1t+MtGC9rIajBFkCgYEAm6DJp4RuPS5VrKR1O9C0\ng6/ALVXwxEG+aKFSN5T2Rcz+F79+OOoDcpGWVR9i21up1gzVhHqaOaaPP8QMDDMg\n6S6S3zq4si+3CIoQoQqT0a+QWOu9piVDWpPrkFieAqmlx5eYELE9T33W8GrsKiUl\n3L1QKnajCU3sTHEyWCeXS0I=\n-----END PRIVATE KEY-----")
	caCrt := []byte("-----BEGIN CERTIFICATE-----\nMIIFSzCCAzOgAwIBAgIUPMYokV7nMPg1slsklQQ64xvUrLgwDQYJKoZIhvcNAQEL\nBQAwNTETMBEGA1UECgwKUmVkaXMgVGVzdDEeMBwGA1UEAwwVQ2VydGlmaWNhdGUg\nQXV0aG9yaXR5MB4XDTI0MDEyMTA3MjY0OFoXDTM0MDExODA3MjY0OFowNTETMBEG\nA1UECgwKUmVkaXMgVGVzdDEeMBwGA1UEAwwVQ2VydGlmaWNhdGUgQXV0aG9yaXR5\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7F7Ngx7CZcKcST+pUx2h\n/VTTJ/CebW4vOx2nEmkSLp7wvDLYXyZNEu7GfuDDUhVRilN+8n1vk5wmExI4lhR4\ngr/aMWjkAZWVLlwqLMS6FEjX6xCbt/29lUckQrYO/jfk1u1R3dWPdXb3JtcKbs27\nxD/+Gblq5tgOHWZ6Q73Y1UDfr69u2wgduVZMUBSmbnwVJN+AesSs6uyeonzmxIgc\nB20teCGLsbPIwA8GTHaACq6rZjfOs6bu0zWzbsJGhz5dOr2D5i5OtmErJC2H96fI\nIgqVw48fygneB4pqV4KchjHRpShBYxXgxPpbrDkok2J75bwQ7dX70P8HcmquOwCo\nWXkwhd/QKuq5N3+2zogP3/YPQz6CX/rNOfWQklpFBpPn1jaUd0LjSVzXe1hROgTS\nj+jdkq1RXpMIrR9rEMYeGOi0IljvyValXlGmMmwJRnLnXHEmrSLKhafSmATrUt9Q\nONWD9eJCnWOL0PBuwctuSx1Jk2m4o7pKuNzixF+OfbJc7OTp0jsjKj9Y9G8rf4VZ\nzT8nySeVzNLelkz1IPRw/oJ72BNhOu1JzYS6jz9C28Kq/TiLdZmvX86gACSISRp2\nElVxdHRfshiI0BnMaBgLZIwfUUH/TxPAfgTnq6X+VrnVx9PbMhcakQLQtzYc/h7I\nUWQFEnIRNtFkOdS56+vsSiECAwEAAaNTMFEwHQYDVR0OBBYEFDIsZ1L6x4ksBjNa\nLRKeQC9xXXd7MB8GA1UdIwQYMBaAFDIsZ1L6x4ksBjNaLRKeQC9xXXd7MA8GA1Ud\nEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAIb6c8z+EcMfUr03RxoT4qoa\n33zHW3ogJ9MopW2vFozNqCPAyO9HtBZcWO6CGANoSGnVW9IgF964aIoW6uwLSl2R\nDORMKaO00ZiHzUHvh1WnA74Qt2M7UG/DZmszTsTVkA0T3FdVn6RCH2IkNDUmzaXp\nQBNmswqp8sBbaiw2ndCZ0dks/5TCW/TQcjSEtLPtFyxI4oP/KCqDhre0j+Kfgz1c\nnbRsAWvfRKgE5lXIQ/W0pRpo8FSp1GVz9iGnP8UzdO5N98B706q3etzjNSgtNGdk\nxQisI6NwzHtf+/A6hh8aoHHEnJ0e1VRHQ/rR6hg8nyGbTGU3XPon8IwvivnVYRQP\nQ6tnZA2d7LoAv6OUMe1XjMrXSgJ9J6dwwZKU37q1qxdWebjcO60pUfBTM8D1pA7Y\nG8U4DNKr5+025bCmJlWr3QlgPacEp4GqT6d4f5BmJ8y4t3g2lKW0qP5fejjDpoXV\nF5s1Kb2CAfocDybhdHebgacsflCkgwDiIAxHZBJfpND8/TbSve/q6PwSBzLrCXk8\n90hk0sqS22BKAyKHiTK5MoBamf6jcWbQwujut1r3xcpOAySFa5PUhgz/jcbo2M2R\nDsqjI8KON4oRDzNtV7kimgblppBkDnJTz1aXRj0fdaOXqoqBtiIx9B0fyZUgw+Cp\ndZy05zhWYjc7gBLHwsrD\n-----END CERTIFICATE-----")

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
		fileCnt, err = ioutil.ReadFile(confFilePath)
		if err != nil {
			return nil, err
		}
	}

	_, err = os.Stat(confEncFilePath)
	if err == nil {
		cfgFileFound = true
		cfgEncrypted = true
		fileCntTmp, err := ioutil.ReadFile(confEncFilePath)
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
		// TODO: if need delete file `confFile`??
		return ioutil.WriteFile(confEncFile, []byte(fileEncCntB64), 0644)
	}

	return ioutil.WriteFile(confFile, cfgBytes, 0644)
}

func readSensorId() (string, error) {
	cnt, err := ioutil.ReadFile(filepath.Join(common.SensorDir, "uuid"))
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
