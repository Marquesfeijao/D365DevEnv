<#
.SYNOPSIS
    Main menu launcher for D365DevEnv setup scripts.
.DESCRIPTION
    This script provides an interactive menu for managing environment setup tasks for D365DevEnv.
    It checks for PowerShell 7 and prompts installation if missing. The menu allows users to:
      - Run Windows setup tasks
      - Install essential applications
      - Set up the database
    Each option launches the corresponding script in a new PowerShell 7 window.
    The script is modular and imports helper modules for scheduled tasks and PowerShell 7 installation.
.NOTES
    Author: Marquesfeijao
    Repository: D365DevEnv
    Last updated: July 2025
.EXAMPLE
    Run this script in PowerShell to launch the interactive setup menu:
        pwsh.exe -NoProfile -File D365DevEnvMainMenu.ps1
#>

Import-Module "$PSScriptRoot\Set-ScheduledTask.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Install-Powershell7.psm1" -DisableNameChecking

$CurrentPath        = (Get-Location).Path
$FileWindowsSetup   = (Join-Path $CurrentPath "WindowsSetup.ps1")
$FileInstallUpdate  = (Join-Path $CurrentPath "InstallUpdateApps.ps1")
$FileDBSetup        = (Join-Path $CurrentPath "DBSetup.ps1")
$FileStartStop      = (Join-Path $CurrentPath "StartStopServices.ps1")

$DownloadFilesSAS   = (Join-Path $CurrentPath "Download-FileSASLink.ps1")
$FileImportBacpac   = (Join-Path $CurrentPath "Import-Bacpac.ps1")

#region Menu Functions
<#
.SYNOPSIS
    Displays the main menu for D365DevEnv setup options.
.DESCRIPTION
    Shows an interactive menu with options for Windows Update, installing essential apps, database setup, and exit.
    The menu is styled with colors for better readability.
.PARAMETER title
    The title to display at the top of the menu. Defaults to "Main Menu".
.EXAMPLE
    Show-Menu
    Show-Menu -title "Setup Menu"
#>
function Show-Menu{
    param(
        [string]$title = "Main Menu"

    )

    Clear-Host
    Write-Host "===========================$title=============================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Windows Update" -ForegroundColor Cyan
    Write-Host "2. Install Essentials apps" -ForegroundColor Cyan
    Write-Host "3. DB Setup" -ForegroundColor Cyan
    Write-Host "4. Start or Stop Services" -ForegroundColor Cyan
    Write-Host "5. Download Files using SAS link" -ForegroundColor Cyan
    Write-Host "6. Import bacpac file" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "q. Exit" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan

}

<#
.SYNOPSIS
    Displays a message indicating PowerShell 7 is not installed.
.DESCRIPTION
    Shows a styled menu informing the user that PowerShell 7 is required and prompts for installation.
    Used when PowerShell 7 is not detected on the system.
.PARAMETER title
    The title to display at the top of the menu. Defaults to "Main Menu".
.EXAMPLE
    Show-MenuInstallPowerShell
    Show-MenuInstallPowerShell -title "PowerShell Requirement"
#>
function Show-MenuInstallPowerShell{
    param(
        [string]$title = "Main Menu"

    )

    Clear-Host
    Write-Host "===========================$title=============================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "1. PowerShell 7 is not installed. Please install it first." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan

}

<#
.SYNOPSIS
    Displays the main menu and handles user input for launching setup scripts or installing PowerShell 7.
.DESCRIPTION
    This function presents a menu to the user, checks for PowerShell 7, and launches selected scripts in a new window.
    If PowerShell 7 is not installed, prompts the user to install it. Handles exit and invalid selections.
#>
function Menu {
    while ($true) {
        $pwshPath = Get-Command pwsh.exe -ErrorAction SilentlyContinue

        if (-not $pwshPath) {
            Show-MenuInstallPowerShell
            $input = Read-Host "Enter 1 to install PowerShell 7 or 'q' to quit"
            switch ($input) {
                '1' { Install-PowerShell7 }
                'q' { Write-Host "Exiting..."; break }
                default { Write-Host "Invalid selection, please try again." }
            }
        } else {
            Show-Menu
            $input = Read-Host "Select an option (1-4 or 'q' to quit)"
            switch ($input) {
                '1' { Write-Host "Starting Windows Update...";         Start-Process pwsh.exe -ArgumentList "-NoProfile -File $FileWindowsSetup" }
                '2' { Write-Host "Installing Essentials apps...";      Start-Process pwsh.exe -ArgumentList "-NoProfile -File $FileInstallUpdate" }
                '3' { Write-Host "Setting up DB...";                   Start-Process pwsh.exe -ArgumentList "-NoProfile -File $FileDBSetup" }
                '4' { Write-Host "Starting or Stopping Services...";   Start-Process pwsh.exe -ArgumentList "-NoProfile -File $FileStartStop" }
                '5' { Write-Host "Downloading Files using SAS link...";   Start-Process pwsh.exe -ArgumentList "-NoProfile -File $DownloadFilesSAS" }
                '6' { Write-Host "Importing bacpac file...";           Start-Process pwsh.exe -ArgumentList "-NoProfile -File $FileImportBacpac" }

                'q ' { Write-Host "Exiting..."; exit; }
                default { Write-Host "Invalid selection, please try again." }
            }
        }
        Write-Host "Press any key to continue..."
        Write-Host "================================================================"
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
    }
}
#endregion

# Start the main menu
Menu

