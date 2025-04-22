package installer

import (
	"ada/agent/sensor/common"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const sensorDir = "C:\\Program Files\\ada_sensor"

type Installer struct {
	ctx      context.Context
	redisCli *redis.Client
	pkgFile  string
	adaAddr  string
}

func New(adaAddr string) *Installer {
	pkgFile := filepath.Join(sensorDir, "ada_sensor.zip")

	opt := redis.Options{
		Addr:     fmt.Sprintf("%s:6379", adaAddr),
		Password: "1pa2YgE3jfTbVVpn06CN",
	}

	redisCli := redis.NewClient(&opt)
	err := redisCli.Ping(context.Background()).Err()
	if err != nil {
		panic(err)
	}

	return &Installer{ctx: context.Background(), redisCli: redisCli, pkgFile: pkgFile, adaAddr: adaAddr}
}

func (i *Installer) Download() error {
	if !dirExists(sensorDir) {
		if err := os.Mkdir(sensorDir, 0777); err != nil {
			return err
		}
	}

	// 使用redis获取bin file: sum and bytes
	pkgSum, err := i.redisCli.Get(i.ctx, "ada:sensor:latest_pkgsum").Result()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		fmt.Printf("redis get err:%v\n", err)
		return err
	}

	pkgBytes, err := i.redisCli.Get(i.ctx, "ada:sensor:latest_pkgfile").Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		fmt.Printf("redis get err:%v\n", err)
		return err
	}

	if err := os.WriteFile(i.pkgFile, pkgBytes, 0); err != nil {
		fmt.Printf("write sensor package to file err:%v\n", err)
		return err
	}

	fmt.Printf("download sensor package ok, checksum:%s\n", pkgSum)

	hash := sha256.New()
	hash.Write(pkgBytes)
	sumStr := fmt.Sprintf("%x", hash.Sum(nil))
	if sumStr != pkgSum {
		return fmt.Errorf("checksum failed, file_sum:%s, should be:%s\n", sumStr, pkgSum)
	}

	return nil
}

func (i *Installer) Deploy() error {
	defer os.Remove(i.pkgFile)

	pkgDir := filepath.Join(sensorDir, "ada_sensor.pkg")
	defer os.RemoveAll(pkgDir)

	file, err := os.Open(i.pkgFile)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := DeCompress(file, pkgDir); err != nil {
		return err
	}

	files, err := os.Open(filepath.Join(pkgDir, "checksum.txt"))
	if err != nil {
		return err
	}
	defer files.Close()

	scanner := bufio.NewScanner(files)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) != 2 {
			continue
		}

		// part[0] shasum, part[1] filename
		sum, err := i.shasum(filepath.Join(pkgDir, parts[1]))
		if err != nil {
			return err
		}
		if sum != parts[0] {
			return fmt.Errorf("check shasum faild, file:%s, shasum:%s, should be:%s", parts[1], sum, parts[0])
		}
	}

	// 安装npcap-0.93
	if !dirExists("C:\\Program Files\\Npcap") {
		err = i.exec("", []string{filepath.Join(pkgDir, "npcap-0.93.exe"), "/S", "/winpcap_mode=yes", "/loopback_support=no"}, true, 20)
		if err != nil {
			fmt.Printf("[exec] install npcap err:%v", err)
			return err
		}
	}

	// 安装rpcfw
	if !dirExists("C:\\Program Files\\ada_sensor\\rpcfw") {
		rpcFwPath := filepath.Join(pkgDir, "rpcfw.zip")
		file, err := os.OpenFile(rpcFwPath, os.O_RDWR, os.ModePerm)
		if err != nil {
			return err
		}
		if err := DeCompress(file, sensorDir); err != nil {
			return err
		}
	}
	rpcFwBin := filepath.Join(sensorDir, "rpcfw", "rpcFwManager.exe")
	out, err := exec.Command(rpcFwBin, "/status").Output()
	if err != nil {
		return err
	}
	if !strings.Contains(string(out), "RPC Firewall Service installed") {
		err = i.exec(filepath.Join(sensorDir, "rpcfw"), []string{rpcFwBin, "/install"}, true, 10)
		if err != nil {
			fmt.Printf("[exec] install rpcfw err:%v", err)
			return err
		}
	}

	// 安装ldapfw
	if !dirExists("C:\\Program Files\\ada_sensor\\ldapfw") {
		ldapFwPath := filepath.Join(pkgDir, "ldapfw.zip")
		file, err := os.OpenFile(ldapFwPath, os.O_RDWR, os.ModePerm)
		if err != nil {
			return err
		}
		if err := DeCompress(file, sensorDir); err != nil {
			return err
		}
	}
	ldapFwBin := filepath.Join(sensorDir, "ldapfw", common.PlugLdapFwProcName)
	out, err = exec.Command(ldapFwBin, "/status").Output()
	if err != nil {
		fmt.Printf("[exec] status ldapfw err:%v, check if VC_redist.x64 already installed!", err)
		return err
	}

	ldapFwSvcInstalled := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "LDAPFW Installed:") {
			if strings.Contains(line, "True") {
				ldapFwSvcInstalled = true
			}
			break
		}
	}
	if !ldapFwSvcInstalled {
		err = i.exec(filepath.Join(sensorDir, "ldapfw"), []string{ldapFwBin, "/install"}, true, 10)
		if err != nil {
			fmt.Printf("[exec] install ldapfw err:%v", err)
			return err
		}

		// TODO: ldapfw 安装好之后默认会启动，这里先将它停止，待后续通过sensor下发配置启动它

	}

	// 安装sensor
	if err := copyFile(filepath.Join(pkgDir, "ada_sensor.exe"), filepath.Join(sensorDir, "ada_sensor.exe")); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(pkgDir, "sensor.cfg"), filepath.Join(sensorDir, "sensor.cfg")); err != nil {
		return err
	}

	return nil
}

func (i *Installer) Register() error {
	sensorPath := filepath.Join(sensorDir, "ada_sensor.exe")

	// register sensor
	err := i.exec(sensorDir, []string{sensorPath, "-r"}, true, 10)
	if err != nil {
		fmt.Printf("Register sensor err:%v\n", err)
		return err
	}

	// check if sensor register ok
	uuidFile := filepath.Join(sensorDir, "uuid")
	if !exists(uuidFile) {
		fmt.Printf("Register sensor err:%v\n", err)
		return err
	} else {
		uuid, _ := os.ReadFile(uuidFile)
		fmt.Printf("Registered sensor with uuid:%s\n", uuid)
	}

	// check if the ada_sensor service exist
	_, err = exec.Command("powershell.exe", "-nologo", "-noprofile", "Get-Service", "-Name", `"ada_sensor"`).Output()
	if err != nil {
		// this service does not install yet, so we need create the `ada_sensor` service
		err = i.exec("", []string{"New-Service", "-Name", `"ada_sensor"`, "-BinaryPathName", fmt.Sprintf(`"%s"`, sensorPath), "-StartupType", "Automatic"}, false, 10)
		if err != nil {
			fmt.Printf("Create ada_sensor service err:%v\n", err)
			return err
		}
		fmt.Println("Created ada_sensor service ok:")
		out, _ := exec.Command("powershell.exe", "-nologo", "-noprofile", "Get-Service", "-Name", `"ada_sensor"`).Output()
		fmt.Println(string(out))
	}

	return nil
}

func (i *Installer) Start() error {
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			fmt.Printf("delete tmp dir:%s err:%v\n", path, err)
		}
	}(filepath.Join(sensorDir, "ada_sensor.pkg"))

	// restart ada_sensor
	err := i.exec("", []string{"Restart-Service", "-Name", "ada_sensor"}, false, 10)
	if err != nil {
		fmt.Printf("restart ada_sensor service err:%v\n", err)
		return err
	}
	fmt.Println("Restarted ada_sensor service ok:")
	out, _ := exec.Command("powershell.exe", "-nologo", "-noprofile", "Get-Service", "-Name", `"ada_sensor"`).Output()
	fmt.Println(string(out))

	time.Sleep(3 * time.Second)

	return nil
}

func (i *Installer) shasum(file string) (string, error) {
	cnt, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}

	hash := sha256.New()
	hash.Write(cnt)
	sumStr := fmt.Sprintf("%x", hash.Sum(nil))

	return sumStr, nil
}

func (i *Installer) exec(dir string, cmds []string, isCmd bool, timeout int64) error {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()
	}

	var output bytes.Buffer
	var stderr bytes.Buffer
	var c *exec.Cmd

	if !isCmd {
		args := []string{"-nologo", "-noprofile"}
		args = append(args, cmds...)
		c = exec.CommandContext(ctx, "powershell.exe", args...)
	} else {
		cmdsNew := cmds[1:]
		c = exec.CommandContext(ctx, cmds[0], cmdsNew...)
	}
	if dir != "" {
		c.Dir = dir
	}

	c.Stderr = &stderr
	c.Stdout = &output

	if err := c.Run(); err != nil {
		fmt.Printf("exec cmd(%v) err:%v, stdout:%s, stderr %s", cmds, err.Error(), output.String(), stderr.String())
		return err
	}

	fmt.Printf("exec(%s) stdout:%s\n", c.Args, output.String())

	return nil
}
