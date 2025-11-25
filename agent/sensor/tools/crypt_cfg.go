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
	operation   string // "enc" or "dec"
)

func init() {
	flag.StringVar(&confFile, "f", "sensor.yaml", "config file")
	flag.StringVar(&confEncFile, "e", "sensor.cfg", "encrypted config file")
	// Key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
	flag.StringVar(&cfgEncKey, "k", "adcc368715ce1bd5adcc368785ce1bd2", "encryption key (32 bytes for AES-256-GCM)")
	flag.StringVar(&operation, "crypt", "enc", "operation to perform: 'enc' or 'dec'")
}

func main() {
	flag.Parse()

	// Validate key length
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

	aesGCM, err := crypto.NewAesGCM([]byte(cfgEncKey))
	if err != nil {
		return fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}
	fileEncCnt, err := aesGCM.Encrypt(string(fileCnt))
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

	aesGCM, err := crypto.NewAesGCM([]byte(cfgEncKey))
	if err != nil {
		return fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}
	fileCnt, err := aesGCM.Decrypt(sDec)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	err = os.WriteFile(confFile, fileCnt, 0644)
	if err != nil {
		return fmt.Errorf("failed to write decrypted config file %s: %w", confFile, err)
	}
	return nil
}
