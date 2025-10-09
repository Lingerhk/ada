package base

import (
	"errors"
	"reflect"
	"strings"
)

// []string 去重
func RemoveDuplicate(arr []string) (newArr []string) {
	newArr = make([]string, 0)
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return
}

// InArray will search element inside array with any type.
// Will return boolean and index for matched element.
// needle is element to search, haystack is slice of value to be search.
func InArray(needle any, haystack any) bool {
	val := reflect.ValueOf(haystack)
	switch val.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < val.Len(); i++ {
			if reflect.DeepEqual(needle, val.Index(i).Interface()) {
				return true
			}
		}
	case reflect.Map:
		for _, k := range val.MapKeys() {
			if reflect.DeepEqual(needle, val.MapIndex(k).Interface()) {
				return true
			}
		}
	default:
		return false
	}

	return false
}

// 判断obj中是否在target中，支持array/slice/map
func Contain(obj any, target any) (bool, error) {
	targetValue := reflect.ValueOf(target)
	switch reflect.TypeOf(target).Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < targetValue.Len(); i++ {
			if targetValue.Index(i).Interface() == obj {
				return true, nil
			}
		}
	case reflect.Map:
		if targetValue.MapIndex(reflect.ValueOf(obj)).IsValid() {
			return true, nil
		}
	}

	return false, errors.New("not in array")
}

// 从hostname中获取domain
func GetDomainFromHostname(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return parts[0]
	}

	//A.B.C.D A:域控制器 B.C.D:域名
	return strings.Join(parts[1:], ".")
}
