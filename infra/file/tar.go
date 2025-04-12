// author: adaegis
// time: 2020-09-01
// desc:

package file

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
)

// 将文件或目录打包成 .tar 文件
// src 是要打包的文件或目录的路径
// dstTar 是要生成的 .tar.gz 文件的路径
// failIfExist 标记如果 dstTar 文件存在，是否放弃打包，如果否，则会覆盖已存在的文件
func Tar(src string, dstTar string, failIfExist bool) (err error) {
	src = path.Clean(src)
	if !Exists(src) {
		return errors.New("file or directory does not exist:" + src)
	}

	if FileExists(dstTar) {
		if failIfExist {
			return errors.New("file exist:" + dstTar)
		} else {
			if er := os.Remove(dstTar); er != nil {
				return er
			}
		}
	}

	fw, er := os.Create(dstTar)
	if er != nil {
		return er
	}
	defer fw.Close()

	gw := gzip.NewWriter(fw)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer func() {
		if er := tw.Close(); er != nil {
			err = er
		}
	}()

	fi, er := os.Stat(src)
	if er != nil {
		return er
	}

	srcBase, srcRelative := path.Split(path.Clean(src))

	if fi.IsDir() {
		err = tarDir(srcBase, srcRelative, tw, fi)
	} else {
		err = tarFile(srcBase, srcRelative, tw, fi)
	}

	return err
}

func tarDir(srcBase, srcRelative string, tw *tar.Writer, fi os.FileInfo) (err error) {
	srcFull := srcBase + srcRelative

	last := len(srcRelative) - 1
	if srcRelative[last] != os.PathSeparator {
		srcRelative += string(os.PathSeparator)
	}

	entries, er := os.ReadDir(srcFull)
	if er != nil {
		return er
	}

	for _, entry := range entries {
		info, er := entry.Info()
		if er != nil {
			continue
		}

		if info.IsDir() {
			_ = tarDir(srcBase, srcRelative+info.Name(), tw, info)
		} else {
			_ = tarFile(srcBase, srcRelative+info.Name(), tw, info)
		}
	}

	if len(srcRelative) > 0 {
		hdr, er := tar.FileInfoHeader(fi, "")
		if er != nil {
			return er
		}
		hdr.Name = srcRelative

		if er = tw.WriteHeader(hdr); er != nil {
			return er
		}
	}

	return nil
}

func tarFile(srcBase, srcRelative string, tw *tar.Writer, fi os.FileInfo) (err error) {
	srcFull := srcBase + srcRelative

	hdr, er := tar.FileInfoHeader(fi, "")
	if er != nil {
		return er
	}
	hdr.Name = srcRelative

	if er = tw.WriteHeader(hdr); er != nil {
		return er
	}

	fr, er := os.Open(srcFull)
	if er != nil {
		return er
	}
	defer fr.Close()

	if _, er = io.Copy(tw, fr); er != nil {
		return er
	}
	return nil
}

func TarMySalt(src, dst, password string) (err error) {
	// 如果存在特殊字符，抛出异常，防止系统命令执行
	for _, ch := range []string{" ", "|", "&"} {
		if strings.Contains(src, ch) {
			return fmt.Errorf("illegal char in src")
		}
		if strings.Contains(dst, ch) {
			return fmt.Errorf("illegal char in dst")
		}
	}

	var tarCmd string
	if password == "" {
		tarCmd = fmt.Sprintf("tar -czvf %s %s", dst, src)
	} else {
		tarCmd = fmt.Sprintf("tar -czvf - %s | openssl des3 -salt -k %s -out %s", src, password, dst)
	}
	c := exec.Command("bash", "-c", tarCmd)
	if err := c.Run(); err != nil {
		return err
	}
	return nil
}
