<#
.SYNOPSIS
    Initializes the script by setting up the environment and installing required components.
.DESCRIPTION
    This function performs the initial setup tasks required for the Windows setup script.
#>
[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$false)]
    [int]$SetStepNumber = 0
)

#region Set up script
$CurrentPath    = $PSScriptRoot
$FileName       = "taskLog.txt"
$LogPath        = $CurrentPath + "\Logs\"

Import-Module "$PSScriptRoot\Set-ScheduledTask.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Install-Powershell7.psm1" -DisableNameChecking

if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Force -Path $LogPath
}

if (!(Test-Path "$LogPath\$FileName")) {
    New-Item -Path "$LogPath\$FileName" -ItemType File -Force
}

if ($SetStepNumber -eq 0) {
    $SetStepNumber = 1
} elseif ($SetStepNumber -notin 1..8) {
    Write-Host "Please enter a valid step number between 1 and 8"
    Exit
}
#endRegion

#region Functions
<# 
.SYNOPSIS
    Initializes the script by setting up the environment and installing required components. 
#>
function Initialize-Script{

    Initialize-Setup
    Install-PowerShell7
}

<# 
.SYNOPSIS
    Writes a log entry to the specified log file.
.DESCRIPTION
    This function appends a log entry to the specified log file, indicating the status of a specific step in the setup process.
.PARAMETER StepProcess
    The process status of the step (e.g., "StepStart", "StepComplete", "StepError").
.PARAMETER StepNum
    The step number being logged.
.PARAMETER PathLog
    The path to the log directory.
.PARAMETER FileName
    The name of the log file.
#>
function Write-Log {
    param (
        [Parameter(Mandatory=$true)][string]$StepProcess,
        [Parameter(Mandatory=$true)][int]$StepNum,
        [Parameter(Mandatory=$true)][string]$PathLog,
        [Parameter(Mandatory=$true)][string]$FileName
    )

    $StepExecution = ""

    try {
        switch ($StepProcess) {
            "StepStart"     { $StepExecution = "Step $StepNum start" }
            "StepComplete"  { $StepExecution = "Step $StepNum complete" }
            "StepError"     { $StepExecution = "Step $StepNum not complete" }
            default         { $StepExecution = "Unknown step process" }
        }

        Write-Output $StepExecution | Out-File "$PathLog\$FileName" -Append -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to write log: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
   Initializes the setup process by configuring necessary settings.
.DESCRIPTION
   This function performs the initial setup tasks required for the Windows setup script.
#>
function Initialize-Setup{

    $registryPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    $name           = "Functions"
    $value          = $(Get-ItemProperty -Path $registryPath -Name $name).Functions
    
    #region Cipher
    $cipher         = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,"
    $cipher         += "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,"
    $cipher         += "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,"
    $cipher         += "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,"
    $cipher         += "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,"
    $cipher         += "TLS_RSA_WITH_AES_256_GCM_SHA384,"
    $cipher         += "TLS_RSA_WITH_AES_128_GCM_SHA256,"
    $cipher         += "TLS_RSA_WITH_AES_256_CBC_SHA256,"
    $cipher         += "TLS_RSA_WITH_AES_128_CBC_SHA256,"
    $cipher         += "TLS_RSA_WITH_AES_256_CBC_SHA,"
    $cipher         += "TLS_RSA_WITH_AES_128_CBC_SHA,"
    $cipher         += "TLS_AES_256_GCM_SHA384,"
    $cipher         += "TLS_AES_128_GCM_SHA256"
    #endregion
    
    if (!($value -eq $cipher))
    {
        Set-ItemProperty -Path $registryPath -Name $name -Value $cipher

        Set-ScheduledTask -TaskName "WindowsSetup-Machine" -StepNumber 1 -Description "Update the cipher" -ScriptToRun "WindowsSetup.ps1"
    }
}
#endRegion

#region Initialize
Initialize-Script
#endregion

#region Steps to run
Write-Host "Step 1 - Set up Nuget"
#region Set up Nuget
if ($SetStepNumber -eq 1) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "Set up Nuget"

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        if (-not (dotnet nuget list source | Select-String -Pattern "nuget.org")) {
            dotnet nuget add source "https://api.nuget.org/v3/index.json" --name "nuget.org"
        }
        
        if (-not (dotnet tool list -g | Select-String -Pattern "^dotnet-vs\s")) {
            dotnet tool install -g dotnet-vs
        } else {
            dotnet tool update -g dotnet-vs
        }
        
        $machinePath    = [System.Environment]::GetEnvironmentVariable("Path","Machine")
        $userPath       = [System.Environment]::GetEnvironmentVariable("Path","User")
        $env:Path       = "$env:Path;$machinePath;$userPath"
        
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 1
        Exit
    }
}
#endRegion

Write-Host "Step 2 - Windows update"
#region Windows update
if ($SetStepNumber -eq 2) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "Windows update"
        # Ensure TLS 1.2 is enabled, but do not overwrite existing protocols
        if (-not ([Net.ServicePointManager]::SecurityProtocol.HasFlag([Net.SecurityProtocolType]::Tls12))) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }

        # Ensure NuGet package provider is available
        try {
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Force -Confirm:$false -ErrorAction Stop
            }
        } catch {
            Write-Host "Failed to install NuGet package provider: $($_.Exception.Message)"
            throw
        }

        # Ensure PSWindowsUpdate module is installed and imported
        try {
            if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Confirm:$false -ErrorAction Stop
            }
            Import-Module PSWindowsUpdate -Force -ErrorAction Stop
        } catch {
            Write-Host "Failed to install or import PSWindowsUpdate: $($_.Exception.Message)"
            throw
        }

        # Run Windows Update steps with error handling
        try {
            Get-WindowsUpdate -Download -ErrorAction Stop
            Get-WindowsUpdate -Install -Verbose -AcceptAll -ErrorAction Stop

            # Check if a reboot is required and prompt the user
            if (Get-WURebootStatus) {
                Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

                $SetStepNumber++

                Set-ScheduledTask -TaskName "WindowsSetup-Machine" -StepNumber $SetStepNumber -Description "Windows update" -ScriptToRun "WindowsSetup.ps1"
            }
        } catch {
            Write-Host "Windows Update failed: $($_.Exception.Message)"
            throw
        }
        
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 2
        Exit
    }
}
#endRegion

Write-Host "Step 3 - Configure Windows Update for Windows 10"
#region Configure Windows Update for Windows 10
if ($SetStepNumber -eq 3) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        if ((Get-WmiObject Win32_OperatingSystem).Caption -Like "*Windows 10*") {
    
            Write-Host "Configure Windows Update for Windows 10"
            #Write-Host "Changing Windows Updates to -Notify to schedule restart-"
            #Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name UxOption -Type DWord -Value 1
        
            Write-Host "Disabling P2P Update downlods outside of local network"
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 3
        }
        
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 3
    }
}
#endRegion

Write-Host "Step 4 - Update PowerShell and PowerShell help"
#region Update PowerShell and PowerShell help
if ($SetStepNumber -eq 4) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        # Update PowerShellGet and PackageManagement modules
        Write-Host "Updating PowerShellGet and PackageManagement modules..."

        if (Get-Module -ListAvailable -Name PowerShellGet) {
            Write-Host "PowerShellGet is already installed. Attempting to update..."
            Update-Module -Name PowerShellGet -Force -ErrorAction Stop
        } else {
            Install-Module -Name PowerShellGet -Force -AllowClobber -ErrorAction Stop
        }

        if (Get-Module -ListAvailable -Name PackageManagement) {
            Write-Host "PackageManagement is already installed. Attempting to update..."
            Update-Module -Name PackageManagement -Force -ErrorAction Stop
        } else {
            Install-Module -Name PackageManagement -Force -AllowClobber -ErrorAction Stop
        }

        Write-Host "If you encounter issues, please restart PowerShell and re-run this script."

        Write-Host "Update PowerShell and PowerShell help"
        # Update PowerShell itself if running Windows PowerShell (not pwsh)
        if ((Get-WmiObject Win32_OperatingSystem).Caption -Like "*Windows 10*" -or (Get-WmiObject Win32_OperatingSystem).Caption -Like "*Windows 11*") {
            Write-Host "Checking for latest PowerShell Core (pwsh)..."
            $pwshPath = Get-Command pwsh.exe -ErrorAction SilentlyContinue
            
            if (-not $pwshPath) {
                Write-Host "Installing PowerShell Core (pwsh)..."
                winget install --id Microsoft.Powershell --source winget --accept-package-agreements --accept-source-agreements
            } 
            else {
                Write-Host "PowerShell Core (pwsh) is already installed."
            }
        }

        # Update help for all modules
        Write-Host "Updating help for all modules..."
        Update-Help -Force -ErrorAction SilentlyContinue

        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Update PowerShell and help Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 4
    }
}
#EndRegion

Write-Host "Step 5 - Set up Power settings"
#region Set up Power settings
if ($SetStepNumber -eq 5) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "Set up Power settings"
        powercfg.exe /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 5
    }
}
#endRegion power settings

Write-Host "Step 6 - Local User Policy"
#region Local User Policy
if ($SetStepNumber -eq 6) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "Local User Policy"
        Write-Host "Set the password to never expire"
        Get-WmiObject Win32_UserAccount -filter "LocalAccount=True" | Where-Object { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1

        Write-Host "Disable changing the password"
        $registryPath   = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $name           = "DisableChangePassword"
        $value          = "1"

        If (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
        }
        else {
            $passwordChangeRegKey = Get-ItemProperty -Path $registryPath -Name $Name -ErrorAction SilentlyContinue

            If (-Not $passwordChangeRegKey) {
                New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
            }
            else {
                Set-ItemProperty -Path $registryPath -Name $name -Value $value
            }
        }
        
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 6
    }
}

#endRegion

Write-Host "Step 7 - Privacy"
#region Privacy
if ($SetStepNumber -eq 7) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "Privacy"
        Write-Host "Start Menu: Disable Bing Search Results"
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0

        if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {    
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
        }

        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0

        if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
        }

        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1

        if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
        }

        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0

        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
        }

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

        Write-Host "Disable Windows Telemetry (requires a reboot to take effect)"
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
        Get-Service DiagTrack, Dmwappushservice | Stop-Service | Set-Service -StartupType Disabled
        
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 7
        Exit
    }
}

#endRegion

Write-Host "Step 8 - Set up browser homepage to local environment"
#region Set up browser homepage to local environment
if ($SetStepNumber -eq 8) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "Set up browser homepage to local environment"

        # Get the local D365 URL
        $d365UrlObj = Get-D365Url
        $URL = $d365UrlObj.Url

        # Set D365 Start Page (if function available)
        if ($d365UrlObj) {
            $d365UrlObj | Set-D365StartPage
        }

        # Set Microsoft Edge homepage via registry
        $edgePolicyPath = 'HKLM:\Software\Policies\Microsoft\Edge'
        $edgeUrlsPath = Join-Path $edgePolicyPath 'RestoreOnStartupURLs'
        $startupValue = 4

        if (!(Test-Path $edgePolicyPath)) {
            New-Item -Path $edgePolicyPath -Force | Out-Null
        }
        Set-ItemProperty -Path $edgePolicyPath -Name 'RestoreOnStartup' -Value $startupValue -PropertyType DWORD -Force

        if (!(Test-Path $edgeUrlsPath)) {
            New-Item -Path $edgeUrlsPath -Force | Out-Null
        }
        Set-ItemProperty -Path $edgeUrlsPath -Name '1' -Value $URL

        Write-Host "The Edge homepage has been set as: $URL"

        # Set Management Reporter to manual startup
        Write-Host "Setting Management Reporter to manual startup to reduce churn and Event Log messages"
        $mrService = Get-D365Environment -FinancialReporter
        if ($mrService) {
            $mrService | Set-Service -StartupType Manual
        }

        # Add Windows Defender exclusions to speed up compilation
        Write-Host "Setting Windows Defender rules to speed up compilation time"
        Add-D365WindowsDefenderRules -Silent

        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up browser homepage Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 8
    }
}
#endRegion
#endregion

if ((Get-ScheduledTask -TaskName "WindowsSetup-Machine" -ErrorAction SilentlyContinue)){
    Unregister-ScheduledTask -TaskName "WindowsSetup-Machine" -Confirm:$false
}