package file

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	logger "github.com/sirupsen/logrus"
)

// Exists checks if a file or directory exists
func Exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// FileExists checks if a file exists
func FileExists(filename string) bool {
	fi, err := os.Stat(filename)
	return err == nil && !fi.IsDir()
}

// DirExists checks if a directory exists
func DirExists(dirname string) bool {
	fi, err := os.Stat(dirname)
	return err == nil && fi.IsDir()
}

// check file or path exist
func PathExist(Path string) bool {
	_, err := os.Stat(Path)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

// parse gzip json
func ParseGzip(data []byte) ([]byte, error) {
	b := new(bytes.Buffer)
	_ = binary.Write(b, binary.LittleEndian, data)
	r, err := gzip.NewReader(b)
	if err != nil {
		logger.Printf("parse gzip error %v", err)
		return nil, err
	}
	defer r.Close()
	result, err := io.ReadAll(r)
	if err != nil {
		logger.Printf("gzip io ReadAll error: %v", err)
		return nil, err
	}
	return result, nil
}

// write file
func WriteFile(fn string, cnt []byte) error {
	f, err := os.OpenFile(fn, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(cnt)
	if err != nil {
		return err
	}

	return nil
}

// GetItemConfFile retrieves the configuration value for the specified key from cfgFile
func GetItemConfFile(cfgFile, key string) (string, error) {
	f, err := os.Open(cfgFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	bs := bufio.NewScanner(f)
	for bs.Scan() {
		line := bs.Text()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		line = strings.TrimSpace(line)
			if strings.HasPrefix(line, key) {
				parts := strings.SplitN(line, "=", 2)
				return strings.TrimSpace(parts[1]), nil
			}
		}
	if err := bs.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("not found")
}
