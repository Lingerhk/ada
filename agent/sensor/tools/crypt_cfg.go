package main

import (
	"ada/infra/crypto"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

var (
	confFile    string
	confEncFile string
	cfgEncKey   string
	operation   string // "enc	" or "dec"
)

func init() {
	flag.StringVar(&confFile, "f", "sensor.yaml", "config file")
	flag.StringVar(&confEncFile, "e", "sensor.cfg", "encrypted config file")
	flag.StringVar(&cfgEncKey, "k", "adcc368715ce1bd2", "encryption key")
	flag.StringVar(&operation, "crypt", "enc", "operation to perform: 'enc' or 'dec'")
}

func main() {
	flag.Parse()

	fmt.Printf("crypt: %s, confFile: %s, confEncFile: %s\n", operation, confFile, confEncFile)

	var err error
	switch operation {
	case "enc":
		err = encryptConfig()
		if err == nil {
			fmt.Println("sensor.cfg encrypted ok!")
		}
	case "dec":
		err = decryptConfig()
		if err == nil {
			fmt.Println("sensor.yaml decrypted ok!")
		}
	default:
		fmt.Println("Invalid operation specified. Use 'enc' or 'dec'.")
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("crypt %s config error: %s\n", operation, err)
		os.Exit(1)
	}
}

func encryptConfig() error {
	fileCnt, err := os.ReadFile(confFile)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", confFile, err)
	}

	aes := crypto.NewAes([]byte(cfgEncKey))
	fileEncCnt, err := aes.Encrypt(string(fileCnt))
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	fileEncCntB64 := base64.StdEncoding.EncodeToString(fileEncCnt)

	err = os.WriteFile(confEncFile, []byte(fileEncCntB64), 0644)
	if err != nil {
		return fmt.Errorf("failed to write encrypted config file %s: %w", confEncFile, err)
	}
	return nil
}

func decryptConfig() error {
	fileEncCntB64, err := os.ReadFile(confEncFile)
	if err != nil {
		return fmt.Errorf("failed to read encrypted config file %s: %w", confEncFile, err)
	}

	sDec, err := base64.StdEncoding.DecodeString(string(fileEncCntB64))
	if err != nil {
		return fmt.Errorf("failed to decode base64 data: %w", err)
	}
	aes := crypto.NewAes([]byte(cfgEncKey))
	fileCnt, err := aes.Decrypt(sDec)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	err = os.WriteFile(confFile, fileCnt, 0644)
	if err != nil {
		return fmt.Errorf("failed to write decrypted config file %s: %w", confFile, err)
	}
	return nil
}
