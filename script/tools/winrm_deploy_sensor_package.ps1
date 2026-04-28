$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$packageUrl = "http://192.168.1.2/download/sensor/adaegis.zip"
$sensorDir = "C:\Program Files\adaegis"
$tsharkDir = Join-Path $sensorDir "tshark"
$tmpRoot = Join-Path $env:TEMP ("adaegis-sensor-package-" + [Guid]::NewGuid().ToString("N"))
$packagePath = Join-Path $tmpRoot "adaegis.zip"
$extractDir = Join-Path $tmpRoot "extract"

New-Item -Path $tmpRoot -ItemType Directory -Force | Out-Null
New-Item -Path $extractDir -ItemType Directory -Force | Out-Null

Write-Output ("package_url=" + $packageUrl)
Invoke-WebRequest -Uri $packageUrl -OutFile $packagePath -UseBasicParsing
Write-Output ("package_bytes=" + (Get-Item $packagePath).Length)

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $extractDir)

$pkgDir = Join-Path $extractDir "pkg"
$pkgTsharkDir = Join-Path $pkgDir "tshark"
$pkgSensorExe = Join-Path $pkgDir "adaegis.exe"
if (!(Test-Path $pkgSensorExe)) {
    throw "adaegis.exe not found in package"
}
if (!(Test-Path (Join-Path $pkgTsharkDir "tshark.exe"))) {
    throw "tshark.exe not found in package"
}

if (!(Test-Path $sensorDir)) {
    New-Item -Path $sensorDir -ItemType Directory -Force | Out-Null
}

$svc = Get-Service -Name "Adaegis" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne "Stopped") {
    Stop-Service -Name "Adaegis" -Force
    $svc.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    Write-Output "adaegis_stopped=true"
}

if (Test-Path $tsharkDir) {
    Remove-Item -Path $tsharkDir -Recurse -Force
}
Copy-Item -Path $pkgTsharkDir -Destination $tsharkDir -Recurse -Force
Copy-Item -Path $pkgSensorExe -Destination (Join-Path $sensorDir "adaegis.exe") -Force

& (Join-Path $tsharkDir "tshark.exe") -v | Select-Object -First 5 | ForEach-Object { Write-Output ("tshark_version=" + $_) }
& (Join-Path $tsharkDir "tshark.exe") -D | Select-Object -First 12 | ForEach-Object { Write-Output ("tshark_iface=" + $_) }

if ($svc) {
    Start-Service -Name "Adaegis"
    Start-Sleep -Seconds 5
    $svc = Get-Service -Name "Adaegis"
    Write-Output ("adaegis_status=" + $svc.Status)
}

& (Join-Path $sensorDir "adaegis.exe") -v | Select-Object -First 6 | ForEach-Object { Write-Output ("sensor_version=" + $_) }

Remove-Item -Path $tmpRoot -Recurse -Force
