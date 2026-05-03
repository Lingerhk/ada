# Bundled TShark Runtime

This directory is the source for the Windows TShark runtime bundled into the
sensor package. The deployed runtime path is:

```text
C:\Program Files\adaegis\tshark\tshark.exe
```

## Source

Use the official Wireshark Windows x64 installer from:

```text
https://www.wireshark.org/download.html
```

Current pinned build:

```text
Wireshark-4.6.5-x64.exe
SHA256: 3c3a2f020d5e053514eefa30dde49e596b857edef6971b655bdfd09af504b0f6
```

Before refreshing this runtime, verify the installer Authenticode signature on
Windows and compare the file hash with the Wireshark signatures file.

## Minimal Runtime

Do not copy only `tshark.exe`. TShark depends on the Wireshark runtime DLLs,
especially `libwireshark.dll`, `libwiretap.dll`, `libwsutil.dll`, GLib, and
compression/crypto/parser libraries.

This directory intentionally contains a minimized runtime, not the full
Wireshark install tree. The minimized package keeps:

```text
pkg\tshark\tshark.exe
pkg\tshark\dumpcap.exe
pkg\tshark\*.dll
pkg\tshark\*.txt
```

The GUI/desktop runtime, media codecs, Qt DLLs, extcap remote capture tools,
protocol plugin directory, profiles, SNMP/MIB data, RADIUS/Diameter dictionaries,
and other non-AD data directories are excluded. The AD protocols currently
needed by the sensor (DNS, LDAP, SMB/SMB2/SMB3, DCE/RPC, Kerberos, NTLM, RDP,
NetBIOS) are decoded by built-in dissectors in `libwireshark.dll`.

The current 38 executable/DLL files are the safe minimum for the official
Wireshark build: every local DLL is directly imported by `tshark.exe`,
`dumpcap.exe`, `libwireshark.dll`, or another required DLL. Further meaningful
size reduction requires a custom Wireshark build or binary compression, both of
which add operational and maintenance risk.

If maintaining the fully extracted runtime is not practical in a checkout,
`pkg\tshark\Wireshark-4.6.5-x64.exe` can be included as a bootstrap fallback.
The installer script verifies its SHA256 and Authenticode signature, installs
Wireshark silently, then mirrors `C:\Program Files\Wireshark` into
`C:\Program Files\adaegis\tshark`. Runtime resolution still uses the ADAegis
standalone path first.

Npcap is still required for live capture. The existing sensor installer installs
Npcap from `pkg\npcap-0.93.exe` before starting the ADAegis service.

## Validation

After changing this directory, validate on a Windows DC or equivalent Windows
host with Npcap installed:

```powershell
& "C:\Program Files\adaegis\tshark\tshark.exe" -v
& "C:\Program Files\adaegis\tshark\tshark.exe" -D
& "C:\Program Files\adaegis\tshark\validate-runtime.ps1"
```

Then generate at least LDAP traffic and confirm `ada-packetlog-*` contains a
document with `Protocol=ldap` and `ProtocolFields.ldap`.

The current minimized package was validated in the test environment:

```text
host: 192.168.7.2 backend / 192.168.1.10 DC
sensor: 2.6.22
tshark: Wireshark 4.6.5
zip size with minimized runtime: 65M
runtime directory size: 110M
```

## Deployment

`agent/script/install-adaegis.ps1` extracts `adaegis.zip` into
`C:\Program Files\adaegis\pkg`, then copies `pkg\tshark` to
`C:\Program Files\adaegis\tshark` and verifies:

```powershell
& "C:\Program Files\adaegis\tshark\tshark.exe" -v
```

The installer removes the temporary `pkg` directory after installation, so the
runtime must exist under `C:\Program Files\adaegis\tshark` before the service is
started.

## Sensor Runtime

The sensor resolves TShark in this order:

1. Redis `tshark_path`, when configured.
2. `C:\Program Files\adaegis\tshark\tshark.exe`.
3. System Wireshark fallback paths.
4. `tshark.exe` on `PATH`.

The TShark plugin runs one process per selected interface with the configured
capture/display filters and uses `-T ek` output. Each packet is sent to the
backend as pktlog JSON with `ProtocolFields` containing the decoded TShark
protocol layers.

## Packaging

When building `agent/script/adaegis.zip`, include the runtime directory under
`pkg\tshark`. A valid first-install package must contain at least:

```text
pkg\adaegis.exe
pkg\sensor.cfg
pkg\uninstall-adaegis.ps1
pkg\npcap-0.93.exe
pkg\rpcfw.zip
pkg\ldapfw.zip
pkg\vc_redist.x64.exe
pkg\tshark\tshark.exe
pkg\tshark\dumpcap.exe
pkg\tshark\...
```

The fallback package form is:

```text
pkg\tshark\Wireshark-4.6.5-x64.exe
```

When packaging on macOS, avoid AppleDouble metadata and use deflate compression.
The shared Go zip helper under `infra/file` writes deflated entries; command-line
packaging should use an equivalent zip mode with `COPYFILE_DISABLE=1`.
