package main

import (
	"ada/infra/crypto"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"time"
)

func main() {
	confFile := "./sensor-3.yaml"
	confEncFile := "./sensor-3.cfg"
	const cfgEncKey = "adcc368715ce1bd2"

	var fileCnt []byte
	fileEncCntB64, err := ioutil.ReadFile(confEncFile)
	if err != nil {
		panic(err)
	}

	sDec, err := base64.StdEncoding.DecodeString(string(fileEncCntB64))
	if err != nil {
		panic(err)
	}
	aes := crypto.NewAes([]byte(cfgEncKey))
	fileCnt, err = aes.Decrypt(sDec)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(confFile, fileCnt, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("sensor.yml decrypted ok!")
	time.Sleep(2 * time.Second)
}
