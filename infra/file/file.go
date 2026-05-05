package file

import (
	"os"
)

// Exists checks if a file or directory exists
func Exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
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
