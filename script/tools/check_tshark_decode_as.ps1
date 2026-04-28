$ErrorActionPreference = "Stop"

$tshark = "C:\Program Files\adaegis\tshark\tshark.exe"
if (!(Test-Path $tshark)) {
    throw "tshark.exe not found: $tshark"
}

$decodeAs = @(
    "tcp.port==88,kerberos",
    "udp.port==88,kerberos",
    "tcp.port==464,kerberos",
    "udp.port==464,kerberos",
    "tcp.port==135,dcerpc",
    "tcp.port==593,dcerpc",
    "tcp.port==3389,tpkt",
    "tcp.port==389,ldap",
    "udp.port==389,cldap",
    "udp.port==137,nbns",
    "udp.port==138,nbdgm",
    "tcp.port==139,nbss"
)

foreach ($item in $decodeAs) {
    $process = Start-Process -FilePath $tshark -ArgumentList @("-d", $item, "-v") -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$env:TEMP\tshark-decode-as.out" -RedirectStandardError "$env:TEMP\tshark-decode-as.err"
    $stderr = Get-Content "$env:TEMP\tshark-decode-as.err" -Raw -ErrorAction SilentlyContinue
    if ($process.ExitCode -ne 0) {
        Write-Output "decode_as_failed=$item"
        Write-Output $stderr
        exit $process.ExitCode
    }
    Write-Output "decode_as_ok=$item"
}
