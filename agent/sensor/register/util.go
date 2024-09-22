//go:build windows
// +build windows

package register

import (
	"golang.org/x/sys/windows/registry"
)

func getDomainByRegistry() (string, string, error) {
	var err error
	var domain, hostname string

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return domain, hostname, err
	}
	defer key.Close()

	domain, _, err = key.GetStringValue("Domain")
	if err != nil {
		return domain, hostname, err
	}

	hostname, _, err = key.GetStringValue("Hostname")
	if err != nil {
		return domain, hostname, err
	}

	return domain, hostname, nil
}
