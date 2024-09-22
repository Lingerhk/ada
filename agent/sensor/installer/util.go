package installer

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
)

// 判断档案是否存在
func exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil || os.IsExist(err)
}

// 判断目录是否存在
func dirExists(dirname string) bool {
	fi, err := os.Stat(dirname)
	return (err == nil || os.IsExist(err)) && fi.IsDir()
}

// 复制文件
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	return nil
}

func Close(c io.Closer) {
	err := c.Close()
	if err != nil {
		//log.WithError(err).Error("关闭资源文件失败。")
	}
}

func DeCompress(srcFile *os.File, dstPath string) error {
	// 如果保存路径不存在，创建一个
	if !exists(dstPath) {
		if err := os.MkdirAll(dstPath, os.ModePerm); err != nil {
			debug.PrintStack()
			return err
		}
	}

	// 读取zip文件
	zipFile, err := zip.OpenReader(srcFile.Name())
	if err != nil {
		return err
	}
	defer Close(zipFile)

	// 遍历zip内所有文件和目录
	for _, innerFile := range zipFile.File {
		// 获取该文件数据
		info := innerFile.FileInfo()

		// 如果是目录，则创建一个
		if info.IsDir() {
			err = os.MkdirAll(filepath.Join(dstPath, innerFile.Name), os.ModeDir|os.ModePerm)
			if err != nil {
				return err
			}
			continue
		}

		// 如果文件目录不存在，则创建一个
		dirPath := filepath.Join(dstPath, filepath.Dir(innerFile.Name))
		if !exists(dirPath) {
			if err = os.MkdirAll(dirPath, os.ModeDir|os.ModePerm); err != nil {
				return err
			}
		}

		// 打开该文件
		srcFile, err := innerFile.Open()
		if err != nil {
			continue
		}

		// 创建新文件
		newFilePath := filepath.Join(dstPath, innerFile.Name)
		newFile, err := os.OpenFile(newFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, info.Mode())
		if err != nil {
			continue
		}

		// 拷贝该文件到新文件中
		if _, err := io.Copy(newFile, srcFile); err != nil {
			return err
		}

		// 关闭该文件
		if err := srcFile.Close(); err != nil {
			return err
		}

		// 关闭新文件
		if err := newFile.Close(); err != nil {
			return err
		}
	}
	return nil
}
