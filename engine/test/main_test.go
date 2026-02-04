package test

import (
	"ada/engine/common"
	"ada/engine/config"
	"ada/engine/core"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

const confPath = "/Users/yihuan/project/ada/engine/config/engine.yaml"
const eventFile = "event.txt"

func TestMain(m *testing.M) {
	// init config
	env, err := config.Init(confPath)
	if err != nil {
		panic(err)
	}

	// init engine
	e, err := core.New(env)
	if err != nil {
		panic(err)
	}

	// setup engine
	err = e.Setup()
	if err != nil {
		panic(err)
	}

	// load event data from file into redis queue
	loadEventRdx(env.RedisCli)

	// start sigma matcher
	go e.SigmaMatcher()

	// start flow matcher
	e.Flowset.FlowMatcher(context.Background())

	os.Exit(m.Run())
}

func loadEventRdx(rdxCli *redis.Client) {
	b, err := os.ReadFile(eventFile)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	for _, line := range strings.Split(string(b), "\n") {
		err := rdxCli.LPush(ctx, common.EveLogQueueKey, line).Err()
		if err != nil {
			fmt.Println("redis lpush event err:", err)
		}
	}
}
