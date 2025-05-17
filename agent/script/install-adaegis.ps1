# ADAegis sensor installation script

# Define installation directory
$sensorDir = "C:\Program Files\adaegis"
$adaegisPortal = "http://192.168.6.4"
$logFile = "$sensorDir\install.log"

function Write-Log {
    param (
        [string]$message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -Append -FilePath $logFile
    Write-Host $message
}

try {
    # 1. Create installation directory if not exists
    if (!(Test-Path $sensorDir)) {
        New-Item -Path $sensorDir -ItemType Directory -Force | Out-Null
        Write-Log "Created installation directory: $sensorDir"
    }

    # 2. Download ADAegis package
    Write-Log "Downloading ADAegis package..."
    $packageUrl = "${adaegisPortal}/download/sensor/adaegis.zip"
    $packagePath = "$sensorDir\adaegis.zip"
    $webClient = New-Object System.Net.WebClient
    try {
        $webClient.DownloadFile($packageUrl, $packagePath)
    } catch {
        Write-Log "Error downloading with WebClient: $_. Falling back to Invoke-WebRequest."
        Remove-Item -Path $packagePath -ErrorAction SilentlyContinue # Clean up partially downloaded file if any
        Invoke-WebRequest -Uri $packageUrl -OutFile $packagePath
    } finally {
        if ($webClient -ne $null) {
            $webClient.Dispose()
        }
    }
    Write-Log "Downloaded ADAegis package"

    # 3. Extract ADAegis package
    Write-Log "Extracting ADAegis package..."
    $pkgDir = "$sensorDir\pkg"
    if (Test-Path -Path $pkgDir -PathType Container) {
        Write-Log "Removing existing package directory: $pkgDir"
        Remove-Item -Path $pkgDir -Recurse -Force
        Write-Log "Removed existing package directory: $pkgDir"
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $sensorDir)
    Write-Log "Extracted ADAegis package"

    # 4. Install Npcap if not already installed
    if (!(Test-Path "C:\Program Files\Npcap")) {
        Write-Log "Installing Npcap..."
        Start-Process -FilePath "$sensorDir\pkg\npcap-0.93.exe" -ArgumentList "/S", "/winpcap_mode=yes", "/loopback_support=no" -Wait
        Write-Log "Installed Npcap"
    } else {
        Write-Log "Npcap already installed"
    }

    # 5. Install RPCFW
    $rpcfwDir = "$sensorDir\rpcfw"
    if (!(Test-Path $rpcfwDir)) {
        Write-Log "Installing RPCFW..."
        [System.IO.Compression.ZipFile]::ExtractToDirectory("$sensorDir\pkg\rpcfw.zip", $sensorDir)
    }
    
    $rpcfwBin = "$rpcfwDir\rpcFwManager.exe"
    $rpcService = Get-Service -Name "RPC Firewall" -ErrorAction SilentlyContinue
    if ($null -eq $rpcService) {
        Write-Log "Installing RPCFW service..."
        Start-Process -FilePath $rpcfwBin -ArgumentList "/install" -WorkingDirectory $rpcfwDir -Wait
        Write-Log "Installed RPCFW service"
    } else {
        Write-Log "RPCFW service already installed"
    }

    # 6. Install LDAPFW
    $ldapfwDir = "$sensorDir\ldapfw"
    if (!(Test-Path $ldapfwDir)) {
        Write-Log "Installing LDAPFW..."
        [System.IO.Compression.ZipFile]::ExtractToDirectory("$sensorDir\pkg\ldapfw.zip", $sensorDir)
    }
    
    $ldapfwBin = "$ldapfwDir\ldapFwManager.exe"
    try {
        $ldapService = Get-Service -Name "LDAP Firewall" -ErrorAction SilentlyContinue
        if ($null -eq $ldapService) {
            Write-Log "Installing LDAPFW service..."
            Start-Process -FilePath $ldapfwBin -ArgumentList "/install" -WorkingDirectory $ldapfwDir -Wait
            Write-Log "Installed LDAPFW service"
        } else {
            Write-Log "LDAPFW service already installed"
        }
    } catch {
        Write-Log "Error checking LDAPFW status. Make sure VC_redist.x64 is installed."
        Write-Log "Installing VC_redist.x64..."
        Start-Process -FilePath "$sensorDir\pkg\vc_redist.x64.exe" -ArgumentList "/quiet", "/norestart" -Wait
        Write-Log "Installed VC_redist.x64"
        
        Write-Log "Installing LDAPFW service..."
        Start-Process -FilePath $ldapfwBin -ArgumentList "/install" -WorkingDirectory $ldapfwDir -Wait
        Write-Log "Installed LDAPFW service"
    }

    # 7. Copy ADAegis files
    Write-Log "Copying ADAegis files..."
    Copy-Item -Path "$sensorDir\pkg\adaegis.exe" -Destination "$sensorDir\adaegis.exe" -Force
    Copy-Item -Path "$sensorDir\pkg\sensor.cfg" -Destination "$sensorDir\sensor.cfg" -Force
    Copy-Item -Path "$sensorDir\pkg\uninstall-adaegis.ps1" -Destination "$sensorDir\uninstall-adaegis.ps1" -Force
    Write-Log "Copied ADAegis files"

    # 8. Register ADAegis
    Write-Log "Registering ADAegis sensor..."
    Start-Process -FilePath "$sensorDir\adaegis.exe" -ArgumentList "-r" -WorkingDirectory $sensorDir -Wait
    if (Test-Path "$sensorDir\uuid") {
        $uuid = Get-Content -Path "$sensorDir\uuid"
        Write-Log "Registered ADAegis sensor with UUID: $uuid"
    } else {
        throw "Failed to register ADAegis sensor"
    }

    # 9. Create ADAegis service if it doesn't exist
    $service = Get-Service -Name "Adaegis" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-Log "Creating ADAegis service..."
        New-Service -Name "Adaegis" -BinaryPathName "$sensorDir\adaegis.exe" -StartupType Automatic -Description "ADAegis Sensor Service" | Out-Null
        
        # Configure service recovery options (auto-restart)
        Write-Log "Configuring service recovery options..."
        # Reset/1st/2nd/3rd failure: restart after 30/60/60 seconds
        $cmd = 'sc.exe failure Adaegis reset= 86400 actions= restart/30000/restart/60000/restart/60000'
        Invoke-Expression $cmd
        
        # Set restart parameters for the service
        $cmd = 'sc.exe failureflag Adaegis 1'  # Enable application failure trigger
        Invoke-Expression $cmd
        
        Write-Log "Created ADAegis service with auto-restart"
    } else {
        Write-Log "ADAegis service already exists"
        
        # Configure recovery options even if service exists
        Write-Log "Updating service recovery options..."
        $cmd = 'sc.exe failure Adaegis reset= 86400 actions= restart/30000/restart/60000/restart/60000'
        Invoke-Expression $cmd
        $cmd = 'sc.exe failureflag Adaegis 1'
        Invoke-Expression $cmd
    }

    # 10. Start ADAegis service
    Write-Log "Starting ADAegis service..."
    Start-Service -Name "Adaegis"
    
    # 11. Clean up temporary files
    Write-Log "Cleaning up..."
    Remove-Item -Path $packagePath -Force
    Remove-Item -Path "$sensorDir\pkg" -Recurse -Force

    Start-Sleep -Seconds 1

    # 8. Check if ADAegis service is running
    $service = Get-Service -Name "Adaegis" -ErrorAction SilentlyContinue
    if ($service.Status -eq "Running") {
        Write-Log "ADAegis service is running"
        Write-Host "Installation successful"
    } else {
        Write-Log "ADAegis service is not running"
        throw "ADAegis service failed to start"
    }
} catch {
    Write-Log "Error: $_"
    Write-Host "Installation failed: $_"
    exit 1
}