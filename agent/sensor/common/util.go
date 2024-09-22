package common

import (
	"os"
	"path/filepath"
)

func GetCurrentPath() string {
	basePath, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return os.Args[0]
	}

	return basePath
}
