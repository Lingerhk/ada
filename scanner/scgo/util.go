package scgo

import (
	"ada/infra/crypto"
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt32(v any) (int32, bool) {
	switch x := v.(type) {
	case int:
		return int32(x), true
	case int32:
		return x, true
	case int64:
		return int32(x), true
	case float64:
		return int32(x), true
	case float32:
		return int32(x), true
	case uint:
		return int32(x), true
	case uint32:
		return int32(x), true
	case uint64:
		return int32(x), true
	default:
		return 0, false
	}
}

// asSliceAny converts any slice-like value to []any for uniform iteration.
func asSliceAny(v any) ([]any, bool) {
	switch a := v.(type) {
	case []any:
		return a, true
	case bson.A:
		return []any(a), true
	default:
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Slice {
			return nil, false
		}
		n := rv.Len()
		out := make([]any, n)
		for i := 0; i < n; i++ {
			out[i] = rv.Index(i).Interface()
		}
		return out, true
	}
}

// DecryptDomainPassword mirrors scanner Python util.ecb_decrypt_no_padding (AES-ECB, zero padding, base64 input).
func DecryptDomainPassword(key16, b64Cipher string) (string, error) {
	key := []byte(key16)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("invalid AES key length: %d", len(key))
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Cipher))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	bs := block.BlockSize()
	if len(ciphertext)%bs != 0 {
		return "", fmt.Errorf("ciphertext length %d not multiple of block size %d", len(ciphertext), bs)
	}
	out := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += bs {
		block.Decrypt(out[i:i+bs], ciphertext[i:i+bs])
	}
	return strings.TrimRight(string(out), "\x00"), nil
}

// DecryptDomainPasswordGCM decrypts AES-GCM (nonce+ciphertext+tag) base64 data.
func DecryptDomainPasswordGCM(key32, b64Cipher string) (string, error) {
	key := []byte(key32)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("invalid AES-GCM key length: %d", len(key))
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Cipher))
	if err != nil {
		return "", err
	}
	gcm, err := crypto.NewAesGCM(key)
	if err != nil {
		return "", err
	}
	return gcm.DecryptString(ciphertext)
}

func DialTCP(hostport string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", hostport, timeout)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// FindPythonBin tries to locate a Python executable inside runPath/.venv.
// Prefer python -> python3 -> python3.7, then fallback to system python.
func FindPythonBin(runPath string) string {
	cands := []string{
		filepath.Join(runPath, ".venv", "bin", "python"),
		filepath.Join(runPath, ".venv", "bin", "python3"),
		filepath.Join(runPath, ".venv", "bin", "python3.7"),
		"python3",
		"python",
	}
	for _, c := range cands {
		if strings.Contains(c, string(os.PathSeparator)) {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				return c
			}
			continue
		}
		if lp, err := execLookPath(c); err == nil {
			return lp
		}
	}
	return ""
}

// isolate os/exec.LookPath for easier testing.
var execLookPath = func(file string) (string, error) {
	p, err := exec.LookPath(file)
	if err != nil {
		return "", err
	}
	return p, nil
}

var ErrPluginResultNotFound = errors.New("plugin result marker not found")
