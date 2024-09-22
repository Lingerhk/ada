package upgrade

import (
	"ada/agent/sensor/common"
	"ada/infra/selfupdate"
	"ada/infra/version"
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"sync"
	"time"
)

type Upgrade struct {
	ctx            context.Context
	currentVersion string
	rdxCli         *redis.Client
	Locked         bool // check from other
	thisStop       bool
}

func New(ctx context.Context, rdxCli *redis.Client) *Upgrade {
	return &Upgrade{ctx: ctx, currentVersion: version.BuildVersion, rdxCli: rdxCli}
}

func (u *Upgrade) Once() bool {
	do, newVersion := u.checkUpdate()
	if !do {
		return false
	}

	if err := u.executeUpdate(newVersion); err != nil {
		logger.Errorf("upgrade sensor err:%v", err)
		return false
	}
	return true
}

func (u *Upgrade) Serve(wg *sync.WaitGroup) {
	defer wg.Done()

	upgradeTicker := time.NewTicker(time.Minute)
	defer upgradeTicker.Stop()

	for {
		select {
		case <-u.ctx.Done():
			return
		case <-upgradeTicker.C:
			{
				do, newVersion := u.checkUpdate()
				if !do {
					continue
				}

				if err := u.executeUpdate(newVersion); err != nil {
					logger.Errorf("upgrade sensor err:%v", err)
					continue
				}
			}
		}
	}
}

func (u *Upgrade) checkUpdate() (bool, string) {
	v, err := u.rdxCli.Get(u.ctx, common.SensorLatestVersionKey).Result()
	if err != nil {
		if err == redis.Nil {
			return false, ""
		}
		logger.Errorf("redis get err:%v", err)
		return false, ""
	}

	if v <= u.currentVersion {
		logger.Debugf("no new version for upgrade(latset:%s, current:%s), ignore!", v, u.currentVersion)
		return false, ""
	}

	return true, v
}

func (u *Upgrade) executeUpdate(newVersion string) error {
	defer u.done(newVersion)

	u.Locked = true

	// 使用redis获取bin file: sum and bytes
	binSum, err := u.rdxCli.Get(u.ctx, common.SensorLatestBinSumKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		logger.Errorf("redis get err:%v", err)
		return err
	}

	binBytes, err := u.rdxCli.Get(u.ctx, common.SensorLatestBinFileKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		logger.Errorf("redis get err:%v", err)
		return err
	}

	checksum, err := hex.DecodeString(binSum)
	if err != nil {
		logger.Errorf("hex decode err:%v", err)
		return err
	}

	// 执行自更新
	logger.Infof("start self-update sensor(%s->%s)", u.currentVersion, newVersion)

	err = selfupdate.Apply(bytes.NewReader(binBytes), selfupdate.Options{
		Hash:     crypto.SHA256,
		Checksum: checksum,
	})
	if err != nil {
		logger.Errorf("self-update err:%v", err)
		return err
	}

	logger.Infof("finished self-update sensor to %s", newVersion)

	return nil
}

func (u *Upgrade) done(newVersion string) {
	u.currentVersion = newVersion
	u.Locked = false
}
