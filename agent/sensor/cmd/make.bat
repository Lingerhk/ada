@echo off
echo ADA Sensor Build Script
echo ==========================================
set BuildName=ADA@sensor
set Version=2.6.3
set VersionPath=ada/infra/version
echo Build Version: %Version%
echo Build Name: %BuildName%
echo ==========================================

echo Go build ada_sensor.exe
go build -o ada_sensor.exe -ldflags "-s -w -X %VersionPath%.BuildName=%BuildName% -X %VersionPath%.BuildVersion=%Version%" sensor.go
echo Build ada_sensor.exe success!

timeout /T 5