//go:build tools

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
	operation   string
)

func init() {
	flag.StringVar(&confFile, "f", "sensor.yaml", "config file")
	flag.StringVar(&confEncFile, "e", "sensor.cfg", "encrypted config file")
	flag.StringVar(&cfgEncKey, "k", "adcc368715ce1bd5adcc368785ce1bd2", "encryption key (32 bytes for AES-256-GCM)")
	flag.StringVar(&operation, "crypt", "enc", "operation to perform: 'enc' or 'dec'")
}

func main() {
	flag.Parse()

	keyLen := len(cfgEncKey)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		fmt.Printf("Error: encryption key must be 16, 24, or 32 bytes (got %d bytes)\n", keyLen)
		os.Exit(1)
	}

	fmt.Printf("crypt: %s, confFile: %s, confEncFile: %s\n", operation, confFile, confEncFile)

	var err error
	switch operation {
	case "enc":
		err = encryptConfig()
	case "dec":
		err = decryptConfig()
	default:
		fmt.Printf("Error: invalid operation '%s', must be 'enc' or 'dec'\n", operation)
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

func encryptConfig() error {
	confData, err := os.ReadFile(confFile)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	encData, err := crypto.AESGCMEncryptBase64([]byte(cfgEncKey), confData)
	if err != nil {
		return fmt.Errorf("encrypt config: %w", err)
	}

	return os.WriteFile(confEncFile, []byte(encData), 0644)
}

func decryptConfig() error {
	encData, err := os.ReadFile(confEncFile)
	if err != nil {
		return fmt.Errorf("read encrypted config file: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(string(encData))
	if err != nil {
		return fmt.Errorf("decode base64: %w", err)
	}

	plainData, err := crypto.AESGCMDecrypt([]byte(cfgEncKey), data)
	if err != nil {
		return fmt.Errorf("decrypt config: %w", err)
	}

	return os.WriteFile(confFile, plainData, 0644)
}
