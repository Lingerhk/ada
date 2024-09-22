// author: s0nnet
// time: 2020-09-06
// desc:

package crypto

import (
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"time"
)

// md5String 生成MD5前缀,截断 length 长度.
func MD5String(key string, length int) string {
	h := md5.New()
	h.Write([]byte(key))
	result := hex.EncodeToString(h.Sum(nil))
	if length > len(result) {
		length = len(result)
	}
	return result[:length]
}

// 生成指定长度的随机字符串
// https://colobu.com/2018/09/02/generate-random-string-in-Go/
func RandString(length int) string {
	const (
		letterBytes   = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
		letterIdxBits = 6                    // 6 bits to represent a letter index
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	)

	var src = rand.NewSource(time.Now().UnixNano())
	b := make([]byte, length)

	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := length-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}
