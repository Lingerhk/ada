// author: adaegis
// time: 2023-12-01

package version

import (
	"fmt"
	"os"
	"time"
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
	if args[1] == "-v" {
		fmt.Println("name:", BuildName)
		fmt.Println("version:", BuildVersion)
		fmt.Println("commit version:", CommitVersion)
		fmt.Println("build time:", BuildTime)
		fmt.Println("commit time:", CommitTime)
		fmt.Printf("© %d ADAegis(adaegis.net). All rights reserved.\n", time.Now().Year())
		os.Exit(0)
	}
}

func PrintVersion() {
	fmt.Println("name:", BuildName)
	fmt.Println("version:", BuildVersion)
	fmt.Println("commit version:", CommitVersion)
	fmt.Println("build time:", BuildTime)
	fmt.Println("commit time:", CommitTime)
	fmt.Printf("© %d ADAegis(adaegis.net). All rights reserved.\n", time.Now().Year())
}

func GetBuildVersion() string {
	return BuildVersion
}
