<#
.SYNOPSIS
    Installs or updates PowerShell 7 (pwsh) for Windows Server 2022.
.DESCRIPTION
    Checks whether PowerShell 7 is installed. If not, downloads and silently installs the
    latest stable MSI release from GitHub. If it is installed, checks GitHub for a newer
    release and updates in place when one is available; otherwise leaves the existing
    installation untouched.
#>

Import-Module "$PSScriptRoot\Invoke-WithRetry.psm1" -DisableNameChecking

function Install-PowerShell7 {

    Set-TlsSecurityProtocol

    $pwshCmd         = Get-Command pwsh.exe -ErrorAction SilentlyContinue
    $currentVersion  = $pwshCmd.Version

    if ($pwshCmd) {
        Write-Host "PowerShell 7 is currently installed at: $($pwshCmd.Source) (version $currentVersion)"
    }
    else {
        Write-Host "PowerShell 7 is not installed."
    }

    try {
        $latestRelease = Invoke-WithRetry -OperationName "Query latest PowerShell 7 release" -ScriptBlock {
            Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -UseBasicParsing
        }

        $msiAsset = $latestRelease.assets | Where-Object { $_.name -match 'win-x64\.msi$' -and $_.name -notmatch 'preview' }

        if (-not $msiAsset) {
            Write-Host "Could not find a suitable PowerShell 7 MSI asset for Windows x64."
            return
        }

        $latestVersion = [version]($latestRelease.tag_name.TrimStart('v'))
    }
    catch {
        if ($pwshCmd) {
            Write-Host "Could not check for a newer PowerShell 7 release, continuing to use the installed version $currentVersion. Error: $($_.Exception.Message)"
        }
        else {
            Write-Host "Could not check for the latest PowerShell 7 release and none is installed: $($_.Exception.Message)"
        }
        return
    }

    if ($pwshCmd -and $latestVersion -le $currentVersion) {
        Write-Host "PowerShell 7 is already up to date (version $currentVersion)."
        return
    }

    if ($pwshCmd) {
        Write-Host "Updating PowerShell 7 from $currentVersion to $latestVersion..."
    }
    else {
        Write-Host "Installing PowerShell 7 version $latestVersion..."
    }

    $msiUrl  = $msiAsset.browser_download_url
    $msiName = $msiAsset.name
    $tempMsi = Join-Path $env:TEMP $msiName

    try {
        Invoke-WithRetry -OperationName "Download PowerShell 7 MSI" -ScriptBlock {
            Invoke-WebRequest -Uri $msiUrl -OutFile $tempMsi -UseBasicParsing -ErrorAction Stop
        }
        Write-Host "Downloaded $msiName. Installing..."
        Start-Process msiexec.exe -ArgumentList "/i $tempMsi /qn /norestart" -Wait -NoNewWindow
        Write-Host "PowerShell 7 installation complete."
    }
    catch {
        Write-Host "Failed to download or install PowerShell 7: $($_.Exception.Message)"
        return
    }
    finally {
        if (Test-Path $tempMsi) { Remove-Item $tempMsi -Force }
    }

    # The installer updates the Machine/User PATH in the registry, not this process's
    # already-loaded $env:Path, so refresh it before re-checking for pwsh.exe.
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

    $pwshPathAfterInstall = Get-Command pwsh.exe -ErrorAction SilentlyContinue

    if ($pwshPathAfterInstall) {
        Write-Host "PowerShell 7 is now installed at: $($pwshPathAfterInstall.Source) (version $($pwshPathAfterInstall.Version))"
    }
    else {
        Write-Host "PowerShell 7 installation did not complete successfully."
    }
}
