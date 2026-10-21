package fwctl

import (
	"bytes"
	"strings"
)

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
