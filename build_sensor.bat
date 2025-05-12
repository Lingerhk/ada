@echo off
setlocal

echo [!] This script must run in windows

:: --- Configuration ---
set Version=2.6.3
set ImageName=ada_sensor:%Version%

echo ==========================================
echo Sensor Build Script
echo Version: %Version%
echo Image Name: %ImageName%
echo ==========================================

:: --- Check and Delete Existing Image ---
echo Checking for existing image %ImageName%...
docker image inspect %ImageName% > nul 2>&1
if %errorlevel% equ 0 (
    echo Found existing image. Deleting %ImageName%...
    docker rmi -f %ImageName%
    if %errorlevel% neq 0 (
        echo Failed to delete existing image %ImageName%. Exiting.
        goto :error_no_popd
    )
    echo Image deleted successfully.
) else (
    echo No existing image found.
)

:: --- Build Docker Image ---
echo Building docker image %ImageName%...
copy script\docker\sensor\Dockerfile Dockerfile /Y
docker build -t %ImageName% .
if errorlevel 1 (
    echo Docker build failed. Cleaning up and exiting.
    del Dockerfile > nul 2>&1
    goto :error
)
echo Docker image built successfully.
del Dockerfile > nul 2>&1


echo Creating temporary container...
set TempContainerName=temp_sensor_docker_%RANDOM%
docker create --name %TempContainerName% %ImageName%
if errorlevel 1 (
    echo Failed to create temporary container. Cleaning up and exiting.
    docker rmi -f %ImageName% > nul 2>&1
    goto :error
)

:: --- Copy Binary from Container ---
docker cp %TempContainerName%:\app\agent\sensor\cmd\ada_sensor.exe ada_sensor.exe

:: --- Remove Temporary Container ---
echo Removing temporary container %TempContainerName%...
docker rm %TempContainerName% > nul 2>&1


echo Deleting build image %ImageName%...
docker rmi -f %ImageName%
if errorlevel 1 (
    echo Warning: Failed to delete image %ImageName%. It might be in use or already deleted.
) else (
    echo Image %ImageName% deleted successfully.
)


echo ==========================================
echo Build and Extraction Complete!
echo ada_sensor.exe is in the current directory
echo ==========================================


:error
echo.
echo !!! An error occurred during the build process. !!!
popd
endlocal
exit /b 1

:error_no_popd
echo.
echo !!! An error occurred. Please check logs. !!!
endlocal
exit /b 1
