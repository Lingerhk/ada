package server

import (
	"ada/backend/apiserver/config"
	"fmt"
	"os"
	"testing"
)

var env *config.Env

func TestMain(m *testing.M) {
	confPath := os.Getenv("APISERVER_CONF_PATH")
	if confPath == "" {
		fmt.Println("get conf path from env failed!")
		return
	}

	var err error
	env, err = config.Init(confPath)
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}
