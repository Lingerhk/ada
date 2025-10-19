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

// 判断档案是否存在
func Exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil && os.IsExist(err)
}

// 判断文件是否存在
func FileExists(filename string) bool {
	fi, err := os.Stat(filename)
	return (err == nil || os.IsExist(err)) && !fi.IsDir()
}

// 判断目录是否存在
func DirExists(dirname string) bool {
	fi, err := os.Stat(dirname)
	return (err == nil || os.IsExist(err)) && fi.IsDir()
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
	_, err = f.Write(cnt)
	if err != nil {
		return err
	}
	defer f.Close()

	return nil
}

// 获取cfgFile中的key相关配置
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

	return "", fmt.Errorf("not found")
}
