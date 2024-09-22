package main

import (
	"ada/infra/otp"
	"crypto/sha1"
	"encoding/base32"
	"flag"
	"fmt"
)

var count, digits int
var trait, mode string

func init() {
	flag.StringVar(&trait, "trait", "xxxxxx", "set trait")
	flag.StringVar(&mode, "mode", "qr_url", "set mode: genqr|code")
	flag.IntVar(&count, "count", 4204, "set count value") // 此值为默认值，在客户现场时，请 +500
	flag.IntVar(&digits, "digits", 8, "set digits")
	flag.Usage = usage
}

func usage() {
	fmt.Println("Usage: builder [cmd]")
	fmt.Println("Example:")
	fmt.Println("\tbuilder -mode genqr -accountName ADA.com -issuerName ada")
	fmt.Println("\tbuilder -mode code -trait xxxx")
	flag.PrintDefaults()
}

func main() {
	flag.Parse()

	secret := base32.StdEncoding.EncodeToString([]byte(trait))

	if mode == "genqr" {
		genURL(secret[:32])
	} else if mode == "code" {
		verifyCode(secret[:32])
	} else {
		fmt.Println("invalid mode, type '-h' for more information.")
	}
}

func genURL(secret string) {
	// 生成URL， 可通过在线二维码生成网站生成
	account := "ADA"
	issuer := "user1.com"
	ret := otp.BuildUri("hotp", secret, account, issuer, "sha1", count, digits, 30)

	fmt.Println("genURL:")
	fmt.Println(ret)
}

func verifyCode(secret string) {
	hasher := &otp.Hasher{
		HashName: "sha1",
		Digest:   sha1.New,
	}

	hotp := otp.NewHOTP(secret, 8, hasher)
	code := hotp.At(count)

	fmt.Println("Maf Code:")
	fmt.Printf("mfa code(count:%d) is: %s\n", count, code)
}
