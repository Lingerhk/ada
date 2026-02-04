package license

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	logger "github.com/sirupsen/logrus"
)

func toBytes(obj any) ([]byte, error) {
	var buffBin bytes.Buffer

	encoderBin := gob.NewEncoder(&buffBin)
	if err := encoderBin.Encode(obj); err != nil {
		return nil, err
	}

	return buffBin.Bytes(), nil
}

func toB64String(obj any) (string, error) {
	b, err := toBytes(obj)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func fromBytes(obj any, b []byte) error {
	buffBin := bytes.NewBuffer(b)
	decoder := gob.NewDecoder(buffBin)

	return decoder.Decode(obj)
}

func fromB64String(obj any, s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	return fromBytes(obj, b)
}

func GetTrait() string {
	//  Temporary solution for testing
	if os.Getenv("TEST_TRAIT") != "" {
		return os.Getenv("TEST_TRAIT")
	}

	var dockerEnv bool
	mid, err := os.ReadFile("/etc/machine-id") // machine server, none-root required
	if err != nil {
		mid, err = os.ReadFile("/var/lib/dbus/machine-id") // machine server,backup, none-root required
		if err != nil {
			mid, err = os.ReadFile("/sys/class/dmi/id/product_uuid") // docker, root required
			dockerEnv = true
		}
	}
	if err != nil {
		return ""
	}

	// Machine ID
	midText := strings.TrimSpace(strings.Trim(string(mid), "\n"))
	if midText == "" {
		dockerEnv = true
	}

	// Machine IPs
	ipsText := getLocalIPText(dockerEnv)

	hasher := md5.New()
	_, err = hasher.Write([]byte(midText + ipsText))
	if err != nil {
		return ""
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func getLocalIPText(dockerEnv bool) string {
	serial, err := os.ReadFile("/sys/class/dmi/id/product_serial")
	if err == nil && string(serial) != "" && dockerEnv {
		return string(serial)
	}

	ignorIface := []string{"docker", "tap", "zt", "br", "lo"}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "interface-err"
	}

	var ips []string
	for _, iface := range ifaces {
		needIgnore := false
		for _, item := range ignorIface {
			if strings.Contains(iface.Name, item) {
				needIgnore = true
				break
			}
		}
		if needIgnore {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			logger.Errorf("ignore err:get addrs by inface %s err:%v", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			ipAddr, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if ipAddr.IP.IsLoopback() {
				continue
			}
			if !ipAddr.IP.IsGlobalUnicast() {
				continue
			}
			if ipAddr.IP.To4() == nil {
				// ignore ipv6 addr
				continue
			}

			if ipAddr.IP.IsPrivate() {
				if dockerEnv {
					ipPrefix := strings.Join(strings.Split(ipAddr.IP.String(), ".")[0:3], ".")
					ips = append(ips, fmt.Sprintf("%s|%s", ipPrefix, ipAddr.Mask.String()))
				} else {
					ips = append(ips, ipAddr.IP.String())
				}
			}
		}

	}

	if len(ips) == 0 {
		return "no-private-ip"
	}

	sort.Strings(ips)
	return strings.Join(ips, ",")
}

func getFingerprint(p1, p2 string) string {
	const fp = "QODXdE8PFxKdqSLKuDA+2ZR9hD2/cEYKXQ=="
	return fmt.Sprintf("%s%s%s%s", publicKeyPrefix, p1, p2, fp)
}
