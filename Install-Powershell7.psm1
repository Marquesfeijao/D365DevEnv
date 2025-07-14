<#
.SYNOPSIS
    Downloads and installs PowerShell 7 (pwsh) for Windows Server 2022.
.DESCRIPTION
    Downloads the latest stable MSI release of PowerShell 7 from GitHub and installs it silently.
    Only runs if pwsh.exe is not already present in the system.
#>
function Install-PowerShell7 {
    
    $pwshPath = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    
    if ($pwshPath) {
        Write-Host "PowerShell 7 is already installed at: $($pwshPath.Source)"
        return
    }

    Write-Host "Downloading latest PowerShell 7 MSI installer..."
    $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -UseBasicParsing
    $msiAsset = $latestRelease.assets | Where-Object { $_.name -match 'win-x64\.msi$' -and $_.name -notmatch 'preview' }
    if (-not $msiAsset) {
        Write-Host "Could not find a suitable PowerShell 7 MSI asset for Windows x64."
        return
    }
    $msiUrl = $msiAsset.browser_download_url
    $msiName = $msiAsset.name
    $tempMsi = Join-Path $env:TEMP $msiName

    try {
        Invoke-WebRequest -Uri $msiUrl -OutFile $tempMsi -UseBasicParsing -ErrorAction Stop
        Write-Host "Downloaded $msiName. Installing..."
        Start-Process msiexec.exe -ArgumentList "/i $tempMsi /qn /norestart" -Wait -NoNewWindow
        Write-Host "PowerShell 7 installation complete."
    } catch {
        Write-Host "Failed to download or install PowerShell 7: $($_.Exception.Message)"
        return
    } finally {
        if (Test-Path $tempMsi) { Remove-Item $tempMsi -Force }
    }

    # Confirm installation
    $pwshPath = Get-Command pwsh.exe -ErrorAction SilentlyContinue

    if ($pwshPath) {
        Write-Host "PowerShell 7 installed successfully at: $($pwshPath.Source)"
    } else {
        Write-Host "PowerShell 7 installation did not complete successfully."
    }
}