package util

import (
	base_common "ada/backend/common"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"ada/backend/apiserver/common"
	"ada/infra/crypto"

	"github.com/golang-jwt/jwt"
)

// 处理err可参考: https://godoc.org/github.com/dgrijalva/jwt-go#ex-Parse--ErrorChecking
// 或jwt.MapClaims的Valid()
type UserClaim struct {
	User    string `json:"user"`
	Role    string `json:"role"`
	Priv    int    `json:"priv"`
	Expired int64  `json:"exp"`
}

func (c UserClaim) Valid() error {
	vErr := new(jwt.ValidationError)
	now := time.Now().Unix()
	if c.Expired == 0 {
		vErr.Inner = fmt.Errorf("exp is required")
		vErr.Errors |= jwt.ValidationErrorClaimsInvalid
	}
	if c.Expired < now {
		delta := time.Unix(now, 0).Sub(time.Unix(c.Expired, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	if c.User == "" {
		vErr.Inner = fmt.Errorf("user is required")
		vErr.Errors |= jwt.ValidationErrorClaimsInvalid
	}

	if c.Role == "" {
		vErr.Inner = fmt.Errorf("role is required")
		vErr.Errors |= jwt.ValidationErrorClaimsInvalid
	}

	if c.Priv == 0 {
		vErr.Inner = fmt.Errorf("priv is required")
		vErr.Errors |= jwt.ValidationErrorClaimsInvalid
	}

	if vErr.Errors == 0 {
		return nil
	}

	return vErr
}

// 解析token获取user消息
func ParseToken(tokenStr, authSecret string) (*UserClaim, error) {
	fn := func(token *jwt.Token) (interface{}, error) {
		return []byte(authSecret), nil
	}

	token, err := jwt.ParseWithClaims(tokenStr, &UserClaim{}, fn)
	if err != nil {
		return nil, err
	}

	claim, ok := token.Claims.(*UserClaim)
	if !ok {
		return nil, errors.New("cannot convert claim to BasicClaim")
	}

	return claim, nil
}

// GenerateToken generates a jwt access token
func GenerateToken(username, role string, priv int32, exp int64) (string, error) {
	claim := UserClaim{
		User:    username,
		Role:    role,
		Priv:    int(priv),
		Expired: exp,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	jwtToken, err := token.SignedString([]byte(common.JWT_SECRET))
	if err != nil {
		return "", err
	}
	return jwtToken, nil
}

// CheckPassStrength check a password strength
func CheckPassStrength(password string) string {
	high := `^(\w|\W)+$`
	middle := `^(((\d|[a-zA-Z])+)|(\d|[~!@#$%^&*_])+|([a-zA-Z]|[~!@#$%^&*_])+)$`
	low := `^(?:\d+|[a-zA-Z]+|[~!@#$%^&*_]+)$`

	if ok, err := regexp.MatchString(low, password); err == nil && ok {
		return "low"
	}
	if ok, err := regexp.MatchString(middle, password); err == nil && ok {
		return "middle"
	}
	if ok, err := regexp.MatchString(high, password); err == nil && ok {
		return "high"
	}

	return "low"
}

// handle ldap sting
// example:
// ldapAddr: ldap://DC01.domain02.com
//
// domain: domain02.com
// domainName: domain02
// dcHostName: DC01
// dn: DC=domain02,DC=com
func LDAPParse(ldapAddr string) (domain, domainName, dcHostName, dn string, err error) {
	ldap, err := url.Parse(ldapAddr)
	if err != nil {
		return "", "", "", "", err
	}
	FQDN := ldap.Host
	parts := strings.Split(FQDN, ".")

	//A.B.C.D A:域控制器 B:dcName B.C.D:域名
	dcHostName = parts[0]
	domainName = parts[1]
	domain = strings.Join(parts[1:], ".")
	dn = "DC=" + strings.Join(parts[1:], ",DC=")

	return
}

func GetDomainFromHostname(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return parts[0]
	}

	//A.B.C.D A:域控制器 B.C.D:域名
	return strings.Join(parts[1:], ".")
}

// ldap password encrypt
func PasswordEncrypt(password string) (encrypt string, err error) {
	aesUtil := crypto.NewAes([]byte(base_common.RDX_CRYPT_SECRET))
	aesEncrypt, err := aesUtil.Encrypt(password)
	if err != nil {
		return "", err
	}
	sEnc := base64.StdEncoding.EncodeToString(aesEncrypt)
	return sEnc, nil
}

// ldap password decode
func PasswordDecode(encrypt string) (password string, err error) {
	aesInstance := crypto.NewAes([]byte(base_common.RDX_CRYPT_SECRET))
	encByte, err := base64.StdEncoding.DecodeString(encrypt)
	if err != nil {
		return "", err
	}
	cfgStr, err := aesInstance.Decrypt(encByte)
	if err != nil {
		return "", err
	}

	return string(cfgStr), nil
}

func Tar(src, dst, password string) (err error) {
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

func Escaping(str string) string {
	fbsArr := []string{"\\", "$", "(", ")", "*", "+", ".", "[", "]", "?", "^", "{", "}", "|"}
	for _, v := range fbsArr {
		str = strings.ReplaceAll(str, v, "\\"+v)
	}
	return str
}
