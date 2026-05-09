package util

import (
	base_common "ada/backend/common"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ada/backend/apiserver/common"
	"ada/infra/crypto"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidJwtToken = errors.New("invalid jwt token")
)

const maxJWTTokenLen = 4096

// 处理err可参考: https://godoc.org/github.com/dgrijalva/jwt-go#ex-Parse--ErrorChecking
// 或jwt.MapClaims的Valid()
type UserClaim struct {
	User    string `json:"user"`
	Role    string `json:"role"`
	Priv    int    `json:"priv"`
	Expired int64  `json:"exp"`
}

func (c UserClaim) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.Expired == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.Expired, 0)), nil
}

func (c UserClaim) GetIssuedAt() (*jwt.NumericDate, error) {
	return nil, nil
}

func (c UserClaim) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

func (c UserClaim) GetIssuer() (string, error) {
	return "", nil
}

func (c UserClaim) GetSubject() (string, error) {
	return "", nil
}

func (c UserClaim) GetAudience() (jwt.ClaimStrings, error) {
	return nil, nil
}

func (c UserClaim) Validate() error {
	var errs []error
	now := time.Now().Unix()
	if c.Expired == 0 {
		errs = append(errs, errors.New("exp is required"))
	}
	if c.Expired < now {
		delta := time.Unix(now, 0).Sub(time.Unix(c.Expired, 0))
		errs = append(errs, fmt.Errorf("token is expired by %v", delta))
	}

	if c.User == "" {
		errs = append(errs, errors.New("user is required"))
	}

	if c.Role == "" {
		errs = append(errs, errors.New("role is required"))
	}

	if c.Priv == 0 {
		errs = append(errs, errors.New("priv is required"))
	}

	return errors.Join(errs...)
}

// 解析token获取user消息
func ParseToken(tokenStr, authSecret string) (*UserClaim, error) {
	if len(tokenStr) < 65 {
		return nil, ErrInvalidJwtToken
	}
	if len(tokenStr) > maxJWTTokenLen {
		return nil, errors.New("jwt token is too large")
	}

	fn := func(token *jwt.Token) (any, error) {
		return []byte(authSecret), nil
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	token, err := parser.ParseWithClaims(tokenStr, &UserClaim{}, fn)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid jwt token")
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

// ldap password encrypt using secure AES-256-GCM
func PasswordEncrypt(password string) (encrypt string, err error) {
	// Use AES-256-GCM for secure authenticated encryption
	aesGCM, err := crypto.NewAesGCM([]byte(base_common.RDX_CRYPT_SECRET))
	if err != nil {
		return "", err
	}

	aesEncrypt, err := aesGCM.Encrypt(password)
	if err != nil {
		return "", err
	}
	sEnc := base64.StdEncoding.EncodeToString(aesEncrypt)
	return sEnc, nil
}

// ldap password decode using secure AES-256-GCM
func PasswordDecode(encrypt string) (password string, err error) {
	// Use AES-256-GCM for secure authenticated decryption
	aesGCM, err := crypto.NewAesGCM([]byte(base_common.RDX_CRYPT_SECRET))
	if err != nil {
		return "", err
	}

	encByte, err := base64.StdEncoding.DecodeString(encrypt)
	if err != nil {
		return "", err
	}

	cfgStr, err := aesGCM.Decrypt(encByte)
	if err != nil {
		return "", err
	}

	return string(cfgStr), nil
}

func Escaping(str string) string {
	fbsArr := []string{"\\", "$", "(", ")", "*", "+", ".", "[", "]", "?", "^", "{", "}", "|"}
	for _, v := range fbsArr {
		str = strings.ReplaceAll(str, v, "\\"+v)
	}
	return str
}
