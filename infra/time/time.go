package time

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// CurTime returns current time, timezone handling to be determined.
func CurTime() time.Time {
	return time.Now()
}

// StrToTime "yyyy-mm-dd hh:mm:ss"
func StrToTime(strTime string) (time.Time, error) {
	return time.ParseInLocation("2006-01-02 15:04:05", strTime, time.Local)
}

// ConvertStrTime converts 10/30s/2h/5m to int64 value in seconds
func ConvertStrTime(s string) (int64, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("empty val:%s", s)
	}

	lastChar := rune(s[len(s)-1])

	if unicode.IsDigit(lastChar) {
		i64, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, err
		}
		return i64, nil
	} else {
		var sec int64
		timeVal := s[:len(s)-1]
		if strings.HasSuffix(s, "s") {
			i64, err := strconv.ParseInt(timeVal, 10, 64)
			if err != nil {
				return 0, err
			}
			sec = i64
		} else if strings.HasSuffix(s, "m") {
			i64, err := strconv.ParseInt(timeVal, 10, 64)
			if err != nil {
				return 0, err
			}
			sec = i64 * 60

		} else if strings.HasSuffix(s, "h") {
			i64, err := strconv.ParseInt(timeVal, 10, 64)
			if err != nil {
				return 0, err
			}
			sec = i64 * 3600
		} else {
			return 0, fmt.Errorf("invalid value:%s", s)
		}

		return sec, nil
	}
}
