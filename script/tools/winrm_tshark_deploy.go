//go:build tools

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"ada/backend/apiserver/util"
	basecommon "ada/backend/common"
	"ada/backend/model"

	"github.com/masterzen/winrm"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func main() {
	var mongoURI string
	var dcIP string
	var dcHostname string
	var winRMHost string
	var winRMPort int
	var installerURL string
	var scriptFile string
	var username string
	var password string
	var domainName string
	var timeout time.Duration

	flag.StringVar(&mongoURI, "mongo-uri", "", "MongoDB URI for db_ada")
	flag.StringVar(&dcIP, "dc-ip", "", "Target DC IP; optional if dc-hostname matches a domain DC list entry")
	flag.StringVar(&dcHostname, "dc-hostname", "", "Target DC hostname; optional if dc-ip is set")
	flag.StringVar(&winRMHost, "winrm-host", "", "Override WinRM connect host, e.g. 127.0.0.1 when using an SSH tunnel")
	flag.IntVar(&winRMPort, "winrm-port", 5985, "Override WinRM connect port")
	flag.StringVar(&installerURL, "installer-url", "", "Wireshark Windows x64 installer URL")
	flag.StringVar(&scriptFile, "script-file", "", "PowerShell script to run instead of the built-in Wireshark installer script")
	flag.StringVar(&username, "username", "", "Explicit WinRM username; skips Mongo lookup when password, domain, and dc-ip are also set")
	flag.StringVar(&password, "password", "", "Explicit WinRM password")
	flag.StringVar(&domainName, "domain", "", "Explicit AD DNS domain, e.g. sevenkingdoms.local")
	flag.DurationVar(&timeout, "timeout", 15*time.Minute, "WinRM command timeout")
	flag.Parse()

	if scriptFile == "" && installerURL == "" {
		panic("installer-url is required unless script-file is set")
	}
	if (username == "" || password == "" || domainName == "" || dcIP == "") && mongoURI == "" {
		panic("mongo-uri is required unless username, password, domain, and dc-ip are set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	targetName := dcIP
	if username == "" || password == "" || domainName == "" || dcIP == "" {
		domain, targetDC, err := loadDomainAndDC(ctx, mongoURI, dcHostname, dcIP)
		if err != nil {
			panic(err)
		}
		if dcIP == "" {
			dcIP = firstIPv4(targetDC.IPList)
		}
		if dcIP == "" {
			panic("target DC IP not found")
		}

		username = domain.LdapConf["user"]
		password, err = util.PasswordDecode(domain.LdapConf["password"])
		if err != nil {
			password, err = legacyPasswordDecode(domain.LdapConf["password"])
			if err != nil {
				panic(fmt.Errorf("decode domain password: %w", err))
			}
		}
		domainName = domain.Name
		targetName = fmt.Sprintf("%s(%s)", targetDC.HostName, dcIP)
	}
	connectHost := dcIP
	if winRMHost != "" {
		connectHost = winRMHost
	}
	endpoint := winrm.NewEndpoint(connectHost, winRMPort, false, false, nil, nil, nil, timeout)
	client, selectedUser, err := authenticatedWinRMClient(ctx, endpoint, username, domainName, password)
	if err != nil {
		panic(err)
	}

	script := installScript(installerURL)
	if scriptFile != "" {
		content, err := os.ReadFile(scriptFile)
		if err != nil {
			panic(err)
		}
		script = string(content)
	}
	stdout, stderr, code, err := client.RunPSWithContext(ctx, script)
	if err != nil {
		panic(fmt.Errorf("winrm run failed: code=%d err=%w stdout=%s stderr=%s", code, err, stdout, stderr))
	}
	if code != 0 {
		panic(fmt.Errorf("winrm script failed: code=%d stdout=%s stderr=%s", code, stdout, stderr))
	}

	fmt.Printf("target=%s domain=%s winrm_user=%s\n", targetName, domainName, selectedUser)
	fmt.Println(stdout)
	if strings.TrimSpace(stderr) != "" {
		fmt.Printf("stderr:\n%s\n", stderr)
	}
}

func authenticatedWinRMClient(ctx context.Context, endpoint *winrm.Endpoint, username, domainName, password string) (*winrm.Client, string, error) {
	var errs []string
	for _, candidate := range usernameCandidates(username, domainName) {
		client, err := winrm.NewClient(endpoint, candidate, password)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", candidate, err))
			continue
		}
		stdout, stderr, code, err := client.RunPSWithContext(ctx, "$env:USERDOMAIN + '\\' + $env:USERNAME")
		if err == nil && code == 0 {
			fmt.Printf("winrm_auth_ok=%s remote_user=%s\n", candidate, strings.TrimSpace(stdout))
			if strings.TrimSpace(stderr) != "" {
				fmt.Printf("winrm_auth_stderr=%s\n", strings.TrimSpace(stderr))
			}
			return client, candidate, nil
		}
		errs = append(errs, fmt.Sprintf("%s: code=%d err=%v stderr=%s", candidate, code, err, strings.TrimSpace(stderr)))
	}
	return nil, "", fmt.Errorf("winrm authentication failed for all username candidates: %s", strings.Join(errs, " | "))
}

func usernameCandidates(username, domainName string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" && !seen[strings.ToLower(v)] {
			seen[strings.ToLower(v)] = true
			out = append(out, v)
		}
	}

	add(username)
	shortDomain := strings.ToUpper(strings.Split(domainName, ".")[0])
	if strings.Contains(username, "@") {
		parts := strings.SplitN(username, "@", 2)
		add(fmt.Sprintf("%s\\%s", shortDomain, parts[0]))
		add(fmt.Sprintf("%s\\%s", parts[1], parts[0]))
		add(fmt.Sprintf(".\\%s", parts[0]))
		add(parts[0])
	}
	if strings.Contains(username, "\\") {
		parts := strings.SplitN(username, "\\", 2)
		add(fmt.Sprintf("%s@%s", parts[1], domainName))
		add(fmt.Sprintf(".\\%s", parts[1]))
		add(parts[1])
	}
	return out
}

func legacyPasswordDecode(encrypted string) (string, error) {
	encByte, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	for _, key := range [][]byte{
		[]byte("3a43d7a31b3ca37d"),
		[]byte(basecommon.RDX_CRYPT_SECRET),
	} {
		plain, err := legacyAesECBDecrypt(encByte, key)
		if err == nil && isPrintableSecret(plain) {
			return string(plain), nil
		}
	}
	return "", errors.New("legacy password decode failed")
}

func isPrintableSecret(v []byte) bool {
	if len(v) == 0 || !utf8.Valid(v) {
		return false
	}
	for _, r := range string(v) {
		if r == utf8.RuneError || !(unicode.IsPrint(r) || unicode.IsSpace(r)) {
			return false
		}
	}
	return true
}

func legacyAesECBDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("legacy aes ecb ciphertext is not full blocks")
	}
	out := make([]byte, len(ciphertext))
	ecb := newECBDecrypter(block)
	ecb.CryptBlocks(out, ciphertext)
	for len(out) > 0 && out[len(out)-1] == 0 {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return nil, errors.New("legacy aes ecb plaintext is empty")
	}
	return out, nil
}

type ecbDecrypter struct {
	b         cipher.Block
	blockSize int
}

func newECBDecrypter(b cipher.Block) cipher.BlockMode {
	return &ecbDecrypter{b: b, blockSize: b.BlockSize()}
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func loadDomainAndDC(ctx context.Context, mongoURI, dcHostname, dcIP string) (*model.Domain, *model.DCList, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
	if err != nil {
		return nil, nil, err
	}
	defer client.Disconnect(ctx)

	cur, err := client.Database("db_ada").Collection((&model.Domain{}).CollectName()).Find(ctx, bson.M{})
	if err != nil {
		return nil, nil, err
	}
	defer cur.Close(ctx)

	for cur.Next(ctx) {
		var domain model.Domain
		if err := cur.Decode(&domain); err != nil {
			return nil, nil, err
		}
		for i := range domain.DCList {
			dc := &domain.DCList[i]
			if dcMatches(dc, dcHostname, dcIP) {
				return &domain, dc, nil
			}
		}
	}
	if err := cur.Err(); err != nil {
		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("no matching domain DC for hostname=%q ip=%q", dcHostname, dcIP)
}

func dcMatches(dc *model.DCList, hostname, ip string) bool {
	if hostname != "" && strings.EqualFold(dc.HostName, hostname) {
		return true
	}
	if ip != "" {
		for _, item := range dc.IPList {
			if item == ip {
				return true
			}
		}
	}
	return false
}

func firstIPv4(ips []string) string {
	for _, ip := range ips {
		if strings.Count(ip, ".") == 3 {
			return ip
		}
	}
	return ""
}

func installScript(installerURL string) string {
	url := strings.ReplaceAll(installerURL, "'", "''")
	return fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$url = '%s'
$installer = Join-Path $env:TEMP 'Wireshark-tshark-installer.exe'
$wiresharkDir = 'C:\Program Files\Wireshark'
$wiresharkTshark = Join-Path $wiresharkDir 'tshark.exe'
$sensorTsharkDir = 'C:\Program Files\adaegis\tshark'
$sensorTshark = Join-Path $sensorTsharkDir 'tshark.exe'

Write-Output "download_url=$url"
Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
$file = Get-Item $installer
Write-Output ("installer_bytes=" + $file.Length)

$sig = Get-AuthenticodeSignature -FilePath $installer
Write-Output ("signature_status=" + $sig.Status)
if ($sig.SignerCertificate) {
  Write-Output ("signature_subject=" + $sig.SignerCertificate.Subject)
}
if ($sig.Status -ne 'Valid') {
  throw "Wireshark installer signature is not valid: $($sig.Status)"
}

$proc = Start-Process -FilePath $installer -ArgumentList '/S','/desktopicon=no' -Wait -PassThru
Write-Output ("installer_exit_code=" + $proc.ExitCode)
if ($proc.ExitCode -ne 0) {
  throw "Wireshark installer failed with exit code $($proc.ExitCode)"
}
if (!(Test-Path $wiresharkTshark)) {
  throw "tshark.exe not found at $wiresharkTshark"
}

if (Test-Path $sensorTsharkDir) {
  Remove-Item -Path $sensorTsharkDir -Recurse -Force
}
New-Item -Path $sensorTsharkDir -ItemType Directory -Force | Out-Null
Copy-Item -Path (Join-Path $wiresharkDir '*') -Destination $sensorTsharkDir -Recurse -Force
if (!(Test-Path $sensorTshark)) {
  throw "standalone tshark.exe not found at $sensorTshark"
}

Write-Output ("tshark_path=" + $sensorTshark)
& $sensorTshark -v | Select-Object -First 4 | ForEach-Object { Write-Output ("tshark_version=" + $_) }
& $sensorTshark -D | Select-Object -First 12 | ForEach-Object { Write-Output ("tshark_iface=" + $_) }

$svc = Get-Service -Name 'Adaegis' -ErrorAction SilentlyContinue
if ($svc) {
  Restart-Service -Name 'Adaegis' -Force
  Start-Sleep -Seconds 5
  $svc = Get-Service -Name 'Adaegis'
  Write-Output ("adaegis_status=" + $svc.Status)
}
`, url)
}
