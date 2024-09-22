echo ADA Sensor Build Script
echo ==========================================
set Version=2.6.0
set VersionPath=ada/infra/version
echo Build Version: %Version%
echo ==========================================

go build -o ada_sensor.exe -ldflags "-s -w -X %VersionPath%.BuildVersion=%Version%" sensor.go

timeout /T 5