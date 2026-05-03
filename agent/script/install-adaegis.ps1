# ADAegis sensor installation script

# Define installation options
$adaegisServer = "YOUR_ADA_SERVER_IP"

$sensorDir = "C:\Program Files\adaegis"
$tsharkDir = "$sensorDir\tshark"
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
    $packageUrl = "http://${adaegisServer}/download/sensor/adaegis.zip"
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
        $process = Start-Process -FilePath "$sensorDir\pkg\npcap-0.93.exe" -ArgumentList "/S", "/winpcap_mode=yes", "/loopback_support=no" -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Npcap installation failed with exit code $($process.ExitCode)"
        }
        Write-Log "Installed Npcap"
    } else {
        Write-Log "Npcap already installed"
    }

    # 5. Install Visual C++ runtime required by LDAPFW and the bundled TShark runtime
    if (Test-Path "$sensorDir\pkg\vc_redist.x64.exe") {
        Write-Log "Installing VC_redist.x64..."
        $process = Start-Process -FilePath "$sensorDir\pkg\vc_redist.x64.exe" -ArgumentList "/quiet", "/norestart" -Wait -PassThru
        if (($process.ExitCode -ne 0) -and ($process.ExitCode -ne 3010)) {
            throw "VC_redist.x64 installation failed with exit code $($process.ExitCode)"
        }
        Write-Log "Installed VC_redist.x64"
    } else {
        Write-Log "vc_redist.x64.exe not found in package"
    }

    # 6. Install RPCFW
    $rpcfwDir = "$sensorDir\rpcfw"
    if (!(Test-Path $rpcfwDir)) {
        Write-Log "Installing RPCFW..."
        [System.IO.Compression.ZipFile]::ExtractToDirectory("$sensorDir\pkg\rpcfw.zip", $sensorDir)
    }
    
    $rpcfwBin = "$rpcfwDir\rpcFwManager.exe"
    $rpcService = Get-Service -Name "RPC Firewall" -ErrorAction SilentlyContinue
    if ($null -eq $rpcService) {
        Write-Log "Installing RPCFW service..."
        $process = Start-Process -FilePath $rpcfwBin -ArgumentList "/install" -WorkingDirectory $rpcfwDir -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "RPCFW service installation failed with exit code $($process.ExitCode)"
        }
        Write-Log "Installed RPCFW service"
    } else {
        Write-Log "RPCFW service already installed"
    }

    # 7. Install LDAPFW
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
            $process = Start-Process -FilePath $ldapfwBin -ArgumentList "/install" -WorkingDirectory $ldapfwDir -Wait -PassThru
            if ($process.ExitCode -ne 0) {
                throw "LDAPFW service installation failed with exit code $($process.ExitCode)"
            }
            Write-Log "Installed LDAPFW service"
        } else {
            Write-Log "LDAPFW service already installed"
        }
    } catch {
        Write-Log "Error checking LDAPFW status. Make sure VC_redist.x64 is installed."
        Write-Log "Installing VC_redist.x64..."
        $process = Start-Process -FilePath "$sensorDir\pkg\vc_redist.x64.exe" -ArgumentList "/quiet", "/norestart" -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "VC_redist.x64 installation failed with exit code $($process.ExitCode)"
        }
        Write-Log "Installed VC_redist.x64"
        
        Write-Log "Installing LDAPFW service..."
        $process = Start-Process -FilePath $ldapfwBin -ArgumentList "/install" -WorkingDirectory $ldapfwDir -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "LDAPFW service installation after VC_redist failed with exit code $($process.ExitCode)"
        }
        Write-Log "Installed LDAPFW service"
    }

    # 8. Install bundled TShark runtime
    $bundledTsharkDir = "$sensorDir\pkg\tshark"
    if (Test-Path "$bundledTsharkDir\tshark.exe") {
        Write-Log "Installing bundled TShark runtime..."
        if (Test-Path -Path $tsharkDir -PathType Container) {
            Remove-Item -Path $tsharkDir -Recurse -Force
        }
        Copy-Item -Path $bundledTsharkDir -Destination $tsharkDir -Recurse -Force
        $process = Start-Process -FilePath "$tsharkDir\tshark.exe" -ArgumentList "-v" -WorkingDirectory $tsharkDir -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -ne 0) {
            throw "Bundled TShark verification failed with exit code $($process.ExitCode)"
        }
        Write-Log "Installed bundled TShark runtime: $tsharkDir\tshark.exe"
    } elseif (Test-Path "$bundledTsharkDir\Wireshark-4.6.5-x64.exe") {
        Write-Log "Bundled TShark runtime not found; bootstrapping from bundled Wireshark installer..."
        $wiresharkInstaller = "$bundledTsharkDir\Wireshark-4.6.5-x64.exe"
        $expectedHash = "3c3a2f020d5e053514eefa30dde49e596b857edef6971b655bdfd09af504b0f6"
        $actualHash = (Get-FileHash -Path $wiresharkInstaller -Algorithm SHA256).Hash.ToLower()
        if ($actualHash -ne $expectedHash) {
            throw "Wireshark installer SHA256 mismatch: $actualHash"
        }
        $sig = Get-AuthenticodeSignature -FilePath $wiresharkInstaller
        if ($sig.Status -ne "Valid") {
            throw "Wireshark installer signature is not valid: $($sig.Status)"
        }
        $process = Start-Process -FilePath $wiresharkInstaller -ArgumentList "/S", "/desktopicon=no" -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Wireshark installer failed with exit code $($process.ExitCode)"
        }
        $wiresharkDir = "C:\Program Files\Wireshark"
        if (!(Test-Path "$wiresharkDir\tshark.exe")) {
            throw "Wireshark installer completed but tshark.exe was not found at $wiresharkDir"
        }
        if (Test-Path -Path $tsharkDir -PathType Container) {
            Remove-Item -Path $tsharkDir -Recurse -Force
        }
        New-Item -Path $tsharkDir -ItemType Directory -Force | Out-Null
        Copy-Item -Path "$wiresharkDir\*" -Destination $tsharkDir -Recurse -Force
        $process = Start-Process -FilePath "$tsharkDir\tshark.exe" -ArgumentList "-v" -WorkingDirectory $tsharkDir -Wait -PassThru -WindowStyle Hidden
        if ($process.ExitCode -ne 0) {
            throw "Bootstrapped TShark verification failed with exit code $($process.ExitCode)"
        }
        Write-Log "Bootstrapped bundled TShark runtime: $tsharkDir\tshark.exe"
    } else {
        Write-Log "Bundled TShark runtime not found at $bundledTsharkDir; tshark plugin will use configured/system fallback path"
    }

    # 9. Copy ADAegis files
    Write-Log "Copying ADAegis files..."
    Copy-Item -Path "$sensorDir\pkg\adaegis.exe" -Destination "$sensorDir\adaegis.exe" -Force
    Copy-Item -Path "$sensorDir\pkg\sensor.cfg" -Destination "$sensorDir\sensor.cfg" -Force
    Copy-Item -Path "$sensorDir\pkg\uninstall-adaegis.ps1" -Destination "$sensorDir\uninstall-adaegis.ps1" -Force
    Write-Log "Copied ADAegis files"

    # 10. update adaegis server into sensor.cfg
    Write-Log "Updating ADAegis server into sensor.cfg..."
    $process = Start-Process -FilePath "$sensorDir\adaegis.exe" -ArgumentList "-m", "${adaegisServer}" -WorkingDirectory $sensorDir -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Failed to update ADAegis server in sensor.cfg. Exit code: $($process.ExitCode)"
    }

    # 11. Register ADAegis
    Write-Log "Registering ADAegis sensor..."
    $process = Start-Process -FilePath "$sensorDir\adaegis.exe" -ArgumentList "-r" -WorkingDirectory $sensorDir -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Failed to register ADAegis sensor. Exit code: $($process.ExitCode)"
    }
    if (Test-Path "$sensorDir\uuid") {
        $uuid = Get-Content -Path "$sensorDir\uuid"
        Write-Log "Registered ADAegis sensor with UUID: $uuid"
    } else {
        throw "Failed to register ADAegis sensor"
    }

    # 12. Create ADAegis service if it doesn't exist
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

    # 13. Start ADAegis service
    Write-Log "Starting ADAegis service..."
    Start-Service -Name "Adaegis"
    
    # 14. Clean up temporary files
    Write-Log "Cleaning up..."
    Remove-Item -Path $packagePath -Force
    Remove-Item -Path "$sensorDir\pkg" -Recurse -Force

    Start-Sleep -Seconds 1

    # 15. Check if ADAegis service is running
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
