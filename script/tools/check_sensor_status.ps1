$ErrorActionPreference = "Stop"

$sensorDir = "C:\Program Files\adaegis"
$sensorExe = Join-Path $sensorDir "adaegis.exe"
$svc = Get-Service -Name "Adaegis" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Output ("adaegis_status=" + $svc.Status)
} else {
    Write-Output "adaegis_status=missing"
}

if (Test-Path $sensorExe) {
    Write-Output ("adaegis_hash=" + (Get-FileHash $sensorExe -Algorithm SHA256).Hash.ToLower())
    & $sensorExe -v | Select-Object -First 6 | ForEach-Object { Write-Output ("sensor_version=" + $_) }
} else {
    Write-Output "adaegis_exe=missing"
}

$tshark = Join-Path $sensorDir "tshark\tshark.exe"
if (Test-Path $tshark) {
    & $tshark -v | Select-Object -First 1 | ForEach-Object { Write-Output ("tshark_version=" + $_) }
} else {
    Write-Output "tshark=missing"
}
