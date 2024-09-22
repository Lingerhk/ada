// author: s0nnet
// time: 2020-09-14
// desc:

package file

import (
	"archive/zip"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime/debug"
)

func Compress(files []*os.File, dest string) error {
	d, _ := os.Create(dest)
	defer Close(d)
	w := zip.NewWriter(d)
	defer Close(w)
	for _, file := range files {
		if err := _Compress(file, "", w); err != nil {
			return err
		}
	}
	return nil
}

func CompressOne(file *os.File, dest string) error {
	d, _ := os.Create(dest)
	defer Close(d)
	w := zip.NewWriter(d)
	defer Close(w)

	if err := _Compress(file, "", w); err != nil {
		return err
	}

	return nil
}

func _Compress(file *os.File, prefix string, zw *zip.Writer) error {
	info, err := file.Stat()
	if err != nil {
		debug.PrintStack()
		return err
	}
	if info.IsDir() {
		prefix = prefix + "/" + info.Name()
		fileInfos, err := file.Readdir(-1)
		if err != nil {
			debug.PrintStack()
			return err
		}
		for _, fi := range fileInfos {
			f, err := os.Open(file.Name() + "/" + fi.Name())
			if err != nil {
				debug.PrintStack()
				return err
			}
			err = _Compress(f, prefix, zw)
			if err != nil {
				debug.PrintStack()
				return err
			}
		}
	} else {
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			debug.PrintStack()
			return err
		}
		header.Name = prefix + "/" + header.Name
		writer, err := zw.CreateHeader(header)
		if err != nil {
			debug.PrintStack()
			return err
		}
		_, err = io.Copy(writer, file)
		Close(file)
		if err != nil {
			debug.PrintStack()
			return err
		}
	}
	return nil
}

func Close(c io.Closer) {
	err := c.Close()
	if err != nil {
		//log.WithError(err).Error("关闭资源文件失败。")
	}
}

func GetFilesFromDir(dirPath string) ([]*os.File, error) {
	var res []*os.File
	for _, fInfo := range ListDir(dirPath) {
		f, err := os.Open(filepath.Join(dirPath, fInfo.Name()))
		if err != nil {
			return res, err
		}
		res = append(res, f)
	}
	return res, nil
}

func ListDir(path string) []os.FileInfo {
	list, err := ioutil.ReadDir(path)
	if err != nil {
		debug.PrintStack()
		return nil
	}
	return list
}

func DeCompress(srcFile *os.File, dstPath string) error {
	// 如果保存路径不存在，创建一个
	if !Exists(dstPath) {
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
		if !Exists(dirPath) {
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
