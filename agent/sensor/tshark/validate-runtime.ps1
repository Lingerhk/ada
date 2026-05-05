$ErrorActionPreference = "Stop"

$runtimeDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$tshark = Join-Path $runtimeDir "tshark.exe"
$dumpcap = Join-Path $runtimeDir "dumpcap.exe"

$required = @(
    "tshark.exe",
    "dumpcap.exe",
    "brotlicommon.dll",
    "brotlidec.dll",
    "cares.dll",
    "comerr64.dll",
    "libwireshark.dll",
    "libwiretap.dll",
    "libwsutil.dll",
    "glib-2.0-0.dll",
    "gmodule-2.0-0.dll",
    "iconv-2.dll",
    "intl-8.dll",
    "k5sprt64.dll",
    "krb5_64.dll",
    "libffi-8.dll",
    "libgnutls-30.dll",
    "libgcrypt-20.dll",
    "libgmp-10.dll",
    "libgpg-error-0.dll",
    "libhogweed-6.dll",
    "libiconv-2.dll",
    "libintl-8.dll",
    "libnettle-8.dll",
    "libp11-kit-0.dll",
    "libsmi-2.dll",
    "libtasn1-6.dll",
    "libxml2.dll",
    "lua54.dll",
    "lz4.dll",
    "nghttp2.dll",
    "nghttp3.dll",
    "pcre2-8.dll",
    "snappy.dll",
    "xxhash.dll",
    "zlib-ng2.dll",
    "zlib1.dll",
    "zstd.dll"
)

foreach ($file in $required) {
    $path = Join-Path $runtimeDir $file
    if (!(Test-Path $path)) {
        throw "Missing required TShark runtime file: $file"
    }
}

Write-Output "runtime_dir=$runtimeDir"
Write-Output "tshark_version:"
& $tshark -v | Select-Object -First 5

Write-Output "capture_interfaces:"
& $tshark -D | Select-Object -First 16

Write-Output "dumpcap_version:"
& $dumpcap -v | Select-Object -First 3

Write-Output "validation=ok"
