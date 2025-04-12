package main

import (
	"ada/infra/license"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	logger "github.com/sirupsen/logrus"
)

func main() {
	//
	trait := getTrait()
	fmt.Printf("trait:%s\n", trait)

	priKey := "KP+BAwEBC3BrQ29udGFpbmVyAf+CAAECAQNQdWIBCgABAUQB/4QAAAAK/4MFAQL/hgAAAP+Z/4IBYQSPqQDm1TKvlbwx0J4+KRQtLHkI6M75+UJfOGbuMh1AA0JkcHB3JIs2u31nWO6mvKroMonTbFAGNFbbVRM4qjjNWTzgjbLnLkDg13RPDxcSnakiyrgwPtmUfYQ9v3BGCl0BMQJCgLslX3Qw0RQs4CC9s5tV8d68Bbc1+CozzAnAEosvWuMB9+uZ/C84LGVN2uErkJQA"

	//
	licCnt := genLicenseCnt(priKey)
	fmt.Printf("license_key:%s\n", licCnt)
}

func genLicenseCnt(priKey string) string {
	privateKey, err := license.PrivateKeyFromB64String(priKey)
	if err != nil {
		panic(err)
	}

	var licInfo license.LicenseInfo
	licInfo.SnId = "ADA"
	licInfo.Trait = "0cbc8d6a135c939e225882b86e8fab25"
	licInfo.Count = 100
	licInfo.EndTm = time.Now().Add(100 * 24 * time.Hour).Unix()

	docBytes, err := json.Marshal(licInfo)
	if err != nil {
		panic(err)
	}

	lic, err := license.NewLicense(privateKey, docBytes)
	if err != nil {
		panic(err)
	}

	licCntB64, err := lic.ToB64String()
	if err != nil {
		panic(err)
	}

	return licCntB64
}

func getTrait() string {
	mid, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		// try fallback path
		mid, err = os.ReadFile("/var/lib/dbus/machine-id")
	}
	if err != nil {
		return ""
	}

	// 机器ID
	midText := strings.TrimSpace(strings.Trim(string(mid), "\n"))

	// 机器IP
	ipsText := getLocalIPText()

	hasher := md5.New()
	_, err = hasher.Write([]byte(midText + ipsText))
	if err != nil {
		return ""
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func getLocalIPText() string {
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
				ips = append(ips, ipAddr.IP.String())
			}

		}

	}

	if len(ips) == 0 {
		return "no-private-ip"
	}

	sort.Strings(ips)
	return strings.Join(ips, ",")
}
