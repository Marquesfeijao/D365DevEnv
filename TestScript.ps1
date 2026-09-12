<#
.SYNOPSIS
    Scratch script for exercising Install-Addin in isolation, outside the InstallUpdateApps flow.

.DESCRIPTION
    Defines a standalone copy of the Install-Addin function (see InstallUpdateApps.ps1) and
    invokes it immediately, so the TRUDUtilsD365 add-in download/install logic can be tested
    without running the full step-driven InstallUpdateApps.ps1 script.

.NOTES
    Not part of the numbered provisioning step sequence; run manually for ad hoc testing only.
#>
$CurrentPath    = $PSScriptRoot
$FileName       = "taskLog.txt"
$LogPath        = Join-Path $CurrentPath "Logs"
$AddinPath      = Join-Path $CurrentPath "Addin"
$DeployPackages = Join-Path $CurrentPath "DeployablePackages"


#$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
#Set-ItemProperty -Path $regPath -Name "HideFileExt" -Value 0 -Force
#Set-ItemProperty -Path $regPath -Name "AutoCheckSelect" -Value 1 -Force
#Set-ItemProperty -Path $regPath -Name "ShowLibraries" -Value 1 -Force
#Set-ItemProperty -Path $regPath -Name "NavPaneExpandToCurrentFolder" -Value 1 -Force
#Set-ItemProperty -Path $regPath -Name "TaskbarSmallIcons" -Value 1 -Force
#
#Stop-Process -Name explorer -Force
#Start-Process explorer

        try {
            $newDriveName   = "Nostromo"
            $cDrive         = Get-Volume -DriveLetter C -ErrorAction SilentlyContinue

            if ($cDrive) {
                Write-Host "* Renaming C: drive to '$newDriveName'" -ForegroundColor DarkYellow
                Set-Volume -DriveLetter C -NewFileSystemLabel $newDriveName -ErrorAction Stop
            }
            else {
                Write-Warning "C: drive not found. Skipping rename."
            }
        }
        catch {
            Write-Warning "Failed to rename C: drive: $($_.Exception.Message)"
        }