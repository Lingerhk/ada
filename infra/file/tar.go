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

// Tar packages a file or directory into a .tar file
// src is the path of the file or directory to be packaged
// dstTar is the path of the .tar.gz file to be generated
// failIfExist indicates whether to abort packaging if dstTar file exists, if false, will overwrite the existing file
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
			if er = tarDir(srcBase, srcRelative+info.Name(), tw, info); er != nil {
				return er
			}
		} else {
			if er = tarFile(srcBase, srcRelative+info.Name(), tw, info); er != nil {
				return er
			}
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
	// If special characters exist, throw exception to prevent system command execution
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
