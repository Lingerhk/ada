package service

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// sensorCmdPollInterval is how often the result hash of a sensor command is
// checked while waiting for the sensor to acknowledge it.
const sensorCmdPollInterval = time.Second

// waitSensorCmdResult waits until the sensor reports the outcome of a command
// in the Redis hash taskKey (field "succeed" = "1"/"0"), or until timeout or
// ctx expire. It returns whether the command succeeded and the sensor's
// message when it did not.
func waitSensorCmdResult(ctx context.Context, rdx *redis.Client, taskKey string, timeout time.Duration) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(sensorCmdPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, rdx.HGet(context.WithoutCancel(ctx), taskKey, "msg").Val()
		case <-ticker.C:
			switch rdx.HGet(ctx, taskKey, "succeed").Val() {
			case "1":
				return true, ""
			case "0":
				return false, rdx.HGet(ctx, taskKey, "msg").Val()
			}
		}
	}
}
