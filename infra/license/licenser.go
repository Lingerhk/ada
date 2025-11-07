package license

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
)

const publicKeyPrefix = "BI+pAObVMq+VvDHQnj4pFC0seQjozvn5"

type LicenseInfo struct {
	SnId  string `json:"sn"`
	Trait string `json:"trait"`
	Count int    `json:"count"`
	EndTm int64  `json:"end_tm"`
}

type AdaLicence struct {
	rdxCli      *redis.Client
	licCnt      string
	licKeyCache string
	licInfo     LicenseInfo
}

func NewAdaLicense(rdxCli *redis.Client) (*AdaLicence, error) {
	licKey := "ada:license_key"
	licCnt, err := rdxCli.Get(context.Background(), licKey).Result()
	if err != nil {
		if err == redis.Nil {
			logger.Errorf("empty license_key")
			return nil, fmt.Errorf("empty license_key")
		}
		return nil, err
	}
	if licCnt == "" || len(licCnt) != 336 {
		return nil, fmt.Errorf("empty license or invalid license")
	}

	keyCache := rdxCli.Get(context.Background(), "ada:key_cache").Val()
	adaLicense := &AdaLicence{rdxCli: rdxCli, licCnt: licCnt, licKeyCache: keyCache}
	if err := adaLicense.load(); err != nil {
		return nil, err
	}

	return adaLicense, nil
}

func (l *AdaLicence) GetInfo() *LicenseInfo {
	return &l.licInfo
}

func (l *AdaLicence) GetTrait() string {
	return GetTrait()
}

func (l *AdaLicence) UpdateCnt(licNewCnt string) error {
	if err := l.check(licNewCnt); err != nil {
		return err
	}

	licKey := "ada:license_key"
	err := l.rdxCli.Set(context.Background(), licKey, licNewCnt, 0).Err()
	if err != nil {
		return err
	}
	l.licCnt = licNewCnt

	return nil
}

func (l *AdaLicence) Expired() bool {
	// Check if License has expired
	if time.Unix(l.licInfo.EndTm, 0).Before(time.Now()) {
		return true
	}
	return false
}

func (l *AdaLicence) DelayExpired() bool {
	// Check if License has expired for more than 30 days
	if time.Unix(l.licInfo.EndTm, 0).Before(time.Now().Add(-30 * 24 * time.Hour)) {
		return true
	}
	return false
}

func (l *AdaLicence) VerifyCount(count int) bool {
	return l.licInfo.Count > count
}

func (l *AdaLicence) VerifySnId(sn string) bool {
	return sn == l.licInfo.SnId
}

func (l *AdaLicence) load() error {
	const param1 = "Ql84Zu4yHUADQmRwcHckiza7fWdY"
	const param2 = "7qa8qugyidNsUAY0VttVEziqOM1ZPOCNsucu"

	pubKey := getFingerprint(param1, param2)
	publicKey, err := PublicKeyFromB64String(pubKey)
	if err != nil {
		return err
	}
	license, err := LicenseFromB64String(l.licCnt)
	if err != nil {
		return err
	}

	if ok, err := license.Verify(publicKey); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("verify license failed")
	}

	var licInfo LicenseInfo
	if err := json.Unmarshal(license.Data, &licInfo); err != nil {
		return err
	}

	machineTrait := GetTrait()
	if licInfo.Trait != machineTrait {
		return fmt.Errorf("check trait failed, machine trait:%s", machineTrait)
	}

	l.licInfo = licInfo
	// Every load() operation writes current time to redis, sensor will verify if time matches with DC, otherwise sensor stops reporting data
	return l.rdxCli.Set(context.Background(), "ada:server:system_timestamp", time.Now().Unix(), 300*time.Second).Err()
}

func (l *AdaLicence) check(licNewCnt string) error {
	// Verify if new License is valid
	oldLicCnt := l.licCnt
	oldLicInfo := l.licInfo

	l.licCnt = licNewCnt
	if err := l.load(); err != nil {
		l.licCnt = oldLicCnt
		l.licInfo = oldLicInfo
		return err
	}

	return nil
}
