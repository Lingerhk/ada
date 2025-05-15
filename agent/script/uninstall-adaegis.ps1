# ADAegis sensor uninstallation script

$sensorDir = "C:\Program Files\adaegis"
$logFile = "$sensorDir\uninstall.log"

function Write-Log {
    param (
        [string]$message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -Append -FilePath $logFile
    Write-Host $message
}

try {
    Write-Log "Starting ADAegis uninstallation..."

    # 1. Stop the adaegis service if running
    $service = Get-Service -Name "Adaegis" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Log "Stopping ADAegis service..."
        Stop-Service -Name "Adaegis" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Write-Log "ADAegis service stopped"
        
        # 2. Remove the service
        Write-Log "Removing ADAegis service..."
        $serviceRemovalCmd = "sc.exe delete Adaegis"
        Invoke-Expression -Command $serviceRemovalCmd
        Write-Log "ADAegis service removed"
    } else {
        Write-Log "ADAegis service not found"
    }

    # 3. Uninstall RPCFW service if exists
    $rpcfwBin = "$sensorDir\rpcfw\rpcFwManager.exe"
    if (Test-Path $rpcfwBin) {
        Write-Log "Uninstalling RPCFW service..."
        Start-Process -FilePath $rpcfwBin -ArgumentList "/uninstall" -WorkingDirectory "$sensorDir\rpcfw" -Wait -ErrorAction SilentlyContinue
        Write-Log "RPCFW service uninstalled"
    }

    # 4. Uninstall LDAPFW service if exists
    $ldapfwBin = "$sensorDir\ldapfw\ldapFwManager.exe"
    if (Test-Path $ldapfwBin) {
        Write-Log "Uninstalling LDAPFW service..."
        Start-Process -FilePath $ldapfwBin -ArgumentList "/uninstall" -WorkingDirectory "$sensorDir\ldapfw" -Wait -ErrorAction SilentlyContinue
        Write-Log "LDAPFW service uninstalled"
    }

    # 5. Remove the installation directory
    if (Test-Path $sensorDir) {
        Write-Log "Removing ADAegis installation directory..."
        # Add a short delay to ensure all processes are properly terminated
        Start-Sleep -Seconds 3
        
        # Force remove all files and directories
        Remove-Item -Path $sensorDir -Recurse -Force -ErrorAction SilentlyContinue

        # Remove the sub directory or files: C:\Program Files\adaegis\xxx
        Remove-Item -Path "$sensorDir\ldapfw" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$sensorDir\rpcfw" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$sensorDir\logs" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$sensorDir\sensor.cfg" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$sensorDir\adaegis.exe" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$sensorDir\uuid" -Recurse -Force -ErrorAction SilentlyContinue

        # TODO: Noted that this uninstallation script is in the current directory, so it can't delete the directory: C:\Program Files\adaegis
        
        # Check if directory was successfully removed
        if (Test-Path $sensorDir) {
            Write-Log "Warning: Could not remove some files. They may be in use."
        } else {
            Write-Log "ADAegis installation directory removed"
        }
    } else {
        Write-Log "ADAegis installation directory not found"
    }

    # 6. Optional: Keep Npcap for other applications that might need it
    # Uncomment the following lines if you want to uninstall Npcap as well
    <#
    if (Test-Path "C:\Program Files\Npcap") {
        Write-Log "Uninstalling Npcap..."
        $npcapUninstaller = "C:\Program Files\Npcap\uninstall.exe"
        if (Test-Path $npcapUninstaller) {
            Start-Process -FilePath $npcapUninstaller -ArgumentList "/S" -Wait
            Write-Log "Npcap uninstalled"
        }
    }
    #>

    Write-Log "ADAegis uninstallation completed successfully"
    Write-Host "Uninstallation successful"
} catch {
    Write-Log "Error during uninstallation: $_"
    Write-Host "Uninstallation failed: $_"
    exit 1
}
