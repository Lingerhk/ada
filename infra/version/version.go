// author: adaegis
// time: 2023-12-01

package version

import (
	"fmt"
	"os"
)

var (
	BuildName     string
	BuildVersion  string
	BuildTime     string
	CommitVersion string
	CommitTime    string
)

func init() {
	args := os.Args
	if nil == args || len(args) < 2 {
		return
	}
	if "-v" == args[1] {
		fmt.Println("name:", BuildName)
		fmt.Println("version:", BuildVersion)
		fmt.Println("commit version:", CommitVersion)
		fmt.Println("build time:", BuildTime)
		fmt.Println("commit time:", CommitTime)
		fmt.Println("© 2024 AD Protection, Inc.")
		os.Exit(0)
	}
}

func GetBuildVersion() string {
	return BuildVersion
}
