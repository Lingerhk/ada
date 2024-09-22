package server

import "strings"

// 用于mongo中特殊字符替换
func escaping(str string) string {
	fbsArr := []string{"\\", "$", "(", ")", "*", "+", ".", "[", "]", "?", "^", "{", "}", "|"}
	for _, v := range fbsArr {
		str = strings.ReplaceAll(str, v, "\\"+v)
	}
	return str
}
