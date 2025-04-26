@echo off
echo ADA Sensor Build Script
echo ==========================================
set BuildName=ADA@sensor
set Version=2.6.3
for /f "tokens=1* delims==" %%a in ('wmic os get LocalDateTime /value') do if "%%a"=="LocalDateTime" set datetime=%%b
set BuildTime=%datetime:~0,8%_%datetime:~8,6%
set VersionPath=ada/infra/version
set TargetBin=ada_sensor.exe
echo Build Version: %Version%
echo Build Name: %BuildName%
echo Build Time: %BuildTime%
echo ==========================================

::echo Download dependencies(we using vendor mode)
::go mod download

echo Build binary
set GobuildOptions=-ldflags "-s -w -X %VersionPath%.BuildName=%BuildName% -X %VersionPath%.BuildVersion=%Version% -X %VersionPath%.BuildTime=%BuildTime%"
del %TargetBin% > nul 2>&1


:: check if vendor folder exists
set vendorPath=../../../vendor
if exist %vendorPath% (
    echo Vendor folder exists, using vendor mode
    set GobuildOptions=-mod=vendor %GobuildOptions%
)

go build %GobuildOptions% -o %TargetBin% sensor.go

:: check ada_sensor.exe
if not exist %TargetBin% (
    echo Build failed, %TargetBin% not found!
    exit /b 1
)

echo Build %TargetBin% success!