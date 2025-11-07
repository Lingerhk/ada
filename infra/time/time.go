package time

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// CurMSecond returns current time in milliseconds.
func CurMSecond() int64 {
	tm := time.Now()
	return tm.UnixNano() / 1e6
}

// CurTime returns current time, timezone handling to be determined.
func CurTime() time.Time {
	return time.Now()
}

// CurSecond returns current time in seconds.
func CurSecond() int64 {
	tm := time.Now()
	return tm.Unix()
}

// TimeToDate returns yyyy-mm-dd format
func TimeToDate() string {
	tm := time.Now()
	return fmt.Sprintf("%d-%02d-%02d", tm.Year(), tm.Month(), tm.Day())
}

// TimeToDBSufix returns yyyymmdd format
func TimeToDBSufix() string {
	tm := time.Now()
	return fmt.Sprintf("%d%02d%02d", tm.Year(), tm.Month(), tm.Day())
}

// TimeToString returns yyyy-mm-dd hh:mm:ss format
func TimeToString() string {
	tm := time.Now()
	return fmt.Sprintf("%02d-%02d-%02d %02d:%02d:%02d",
		tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second())
}

// StrToTime "yyyy-mm-dd hh:mm:ss"
func StrToTime(strTime string) (time.Time, error) {
	return time.ParseInLocation("2006-01-02 15:04:05", strTime, time.Local)
}

// TimeFormat returns time in specified format (default yyyy-mm-dd hh:mm:ss)
func TimeFormat(tm time.Time, format string) string {
	if format == "" {
		format = "%02d-%02d-%02d %02d:%02d:%02d"
	}

	return fmt.Sprintf(format, tm.Year(), tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second())
}

func TimeAddDate(days int) time.Time {
	cTime := time.Now()
	return cTime.AddDate(0, 0, days)
}

func Str2TimeStamp(str string) (error, int64) {
	formatTime, err := time.Parse(time.RFC3339, str)
	if err != nil {
		return err, 0
	}
	return nil, formatTime.Unix()
}

// FileTime2Time converts file time to time.Time
func FileTime2Time(input int64) time.Time {
	t := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	d := time.Duration(input)
	for i := 0; i < 100; i++ {
		t = t.Add(d)
	}
	return t
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
