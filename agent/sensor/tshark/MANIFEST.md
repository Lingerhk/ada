# TShark Runtime Manifest

Pinned source installer:

```text
Wireshark-4.6.5-x64.exe
SHA256: 3c3a2f020d5e053514eefa30dde49e596b857edef6971b655bdfd09af504b0f6
```

This minimized runtime keeps only `tshark.exe`, `dumpcap.exe`, and the local DLL
closure required by those two binaries. Npcap provides the capture driver and
system packet DLLs on the target host.

The local DLL set was checked as the recursive PE import closure of the two
executables and the required Wireshark DLLs. Apart from the entry-point
executables, every `.dll` in this directory is imported by another retained
binary.

## Required Executables

```text
dumpcap.exe
tshark.exe
```

## Required Local DLLs

```text
brotlicommon.dll
brotlidec.dll
cares.dll
comerr64.dll
glib-2.0-0.dll
gmodule-2.0-0.dll
iconv-2.dll
intl-8.dll
k5sprt64.dll
krb5_64.dll
libffi-8.dll
libgcrypt-20.dll
libgmp-10.dll
libgnutls-30.dll
libgpg-error-0.dll
libhogweed-6.dll
libiconv-2.dll
libintl-8.dll
libnettle-8.dll
libp11-kit-0.dll
libsmi-2.dll
libtasn1-6.dll
libwireshark.dll
libwiretap.dll
libwsutil.dll
libxml2.dll
lua54.dll
lz4.dll
nghttp2.dll
nghttp3.dll
pcre2-8.dll
snappy.dll
xxhash.dll
zlib-ng2.dll
zlib1.dll
zstd.dll
```

## Kept Documentation

```text
COPYING.txt
README.md
README.txt
MANIFEST.md
```

## Excluded From Full Wireshark Runtime

The following categories were removed from the official installer output after
validation because they are not required for current AD packet decoding:

```text
Qt6*.dll
Wireshark.exe
WinSparkle.dll
avcodec-*.dll
avformat-*.dll
avutil-*.dll
swresample-*.dll
swscale-*.dll
opengl32sw.dll
dxcompiler.dll
dxil.dll
plugins/
profiles/
extcap/
diameter/
dtds/
generic/
protobuf/
radius/
snmp/
tls/
tpncp/
wimaxasncp/
*.html
```
