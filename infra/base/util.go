package base

import (
	"errors"
	"reflect"
	"strings"
)

// RemoveDuplicate removes duplicate elements from a string slice
func RemoveDuplicate(arr []string) (newArr []string) {
	newArr = make([]string, 0)
	for i := range len(arr) {
		repeat := false
		for j := range len(arr) - i - 1 {
			if arr[i] == arr[i+j+1] {
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
		for i := range val.Len() {
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

// Contain checks whether obj exists in target, supports array/slice/map
func Contain(obj any, target any) (bool, error) {
	targetValue := reflect.ValueOf(target)
	switch reflect.TypeOf(target).Kind() {
	case reflect.Slice, reflect.Array:
		for i := range targetValue.Len() {
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

// GetDomainFromHostname extracts domain from hostname
func GetDomainFromHostname(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return parts[0]
	}

	// A.B.C.D where A: domain controller, B.C.D: domain name
	return strings.Join(parts[1:], ".")
}
