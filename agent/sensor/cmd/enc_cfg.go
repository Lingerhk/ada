package main

import (
	"ada/infra/crypto"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"time"
)

func main() {
	confFile := "./sensor.yaml"
	confEncFile := "./sensor.cfg"
	const cfgEncKey = "adcc368715ce1bd2"

	var fileCnt, fileEncCnt []byte
	fileCnt, err := ioutil.ReadFile(confFile)
	if err != nil {
		panic(err)
	}

	aes := crypto.NewAes([]byte(cfgEncKey))
	fileEncCnt, err = aes.Encrypt(string(fileCnt))
	if err != nil {
		panic(err)
	}

	fileEncCntB64 := base64.StdEncoding.EncodeToString(fileEncCnt)

	err = ioutil.WriteFile(confEncFile, []byte(fileEncCntB64), 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("sensor.cfg encrypted ok!")
	time.Sleep(2 * time.Second)
}
