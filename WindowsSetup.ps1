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
$LogPath        = Join-Path $CurrentPath "Logs"

Import-Module "$PSScriptRoot\Set-ScheduledTask.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Install-Powershell7.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Write-Log.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Invoke-SetupStep.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Invoke-WithRetry.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Install-OrUpdateModule.psm1" -DisableNameChecking

try {
    Initialize-WorkDirectory -Path $LogPath

    if (!(Test-Path "$LogPath\$FileName")) {
        New-Item -Path "$LogPath\$FileName" -ItemType File -Force | Out-Null
    }
}
catch {
    Write-Host "Failed to initialize Logs directory/file: $($_.Exception.Message)"
    Exit 3
}

Set-TlsSecurityProtocol

$SetStepNumber = Confirm-StepNumber -RequestedStep $SetStepNumber -DefaultStep 1 -MinStep 1 -MaxStep 8
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
   Initializes the setup process by configuring necessary settings.
.DESCRIPTION
   This function performs the initial setup tasks required for the Windows setup script.
#>
function Initialize-Setup{

    $registryPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    $name           = "Functions"
    $value          = $(Get-ItemProperty -Path $registryPath -Name $name -ErrorAction SilentlyContinue).Functions

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
        if (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }

        Set-ItemProperty -Path $registryPath -Name $name -Value $cipher

        Set-ScheduledTask -TaskName "WindowsSetup-Machine" -StepNumber 1 -Description "Update the cipher" -ScriptToRun "WindowsSetup.ps1"
    }
}
#endRegion

#region Initialize
if ($SetStepNumber -eq 1) {
    Initialize-Script
}
#endregion

#region Steps to run
Write-Host "Step 1 - Set up Nuget"
#region Set up Nuget
if ($SetStepNumber -eq 1) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Set up Nuget" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host "Set up Nuget"

        Invoke-WithRetry -OperationName "dotnet nuget source setup" -ScriptBlock {
            if (-not (dotnet nuget list source | Select-String -Pattern "nuget.org")) {
                dotnet nuget add source "https://api.nuget.org/v3/index.json" --name "nuget.org"
            }
        }

        Invoke-WithRetry -OperationName "dotnet-vs tool install/update" -ScriptBlock {
            if (-not (dotnet tool list -g | Select-String -Pattern "^dotnet-vs\s")) {
                dotnet tool install -g dotnet-vs
            } else {
                dotnet tool update -g dotnet-vs
            }
        }

        $machinePath    = [System.Environment]::GetEnvironmentVariable("Path","Machine")
        $userPath       = [System.Environment]::GetEnvironmentVariable("Path","User")
        $env:Path       = "$machinePath;$userPath"
    }
}
#endRegion

Write-Host "Step 2 - Windows update"
#region Windows update
if ($SetStepNumber -eq 2) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Windows update" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host "Windows update"

        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Invoke-WithRetry -OperationName "NuGet package provider install" -ScriptBlock {
                Install-PackageProvider -Name NuGet -Force -Confirm:$false -ErrorAction Stop
            }
        }

        Install-OrUpdateModule -Name PSWindowsUpdate -Import

        Invoke-WithRetry -OperationName "Windows Update download" -ScriptBlock {
            Get-WindowsUpdate -Download -ErrorAction Stop
        }

        Invoke-WithRetry -OperationName "Windows Update install" -ScriptBlock {
            Get-WindowsUpdate -Install -Verbose -AcceptAll -ErrorAction Stop
        }

        # Check if a reboot is required; if so, log completion, register the resume task, and
        # exit here since the normal post-Action logging in Invoke-SetupStep won't run.
        if (Get-WURebootStatus) {
            Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
            Set-ScheduledTask -TaskName "WindowsSetup-Machine" -StepNumber ($SetStepNumber + 1) -Description "Windows update" -ScriptToRun "WindowsSetup.ps1"
            Exit 0
        }
    }
}
#endRegion

Write-Host "Step 3 - Configure Windows Update for Windows 10"
#region Configure Windows Update for Windows 10
if ($SetStepNumber -eq 3) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Configure Windows Update for Windows 10" -LogPath $LogPath -FileName $FileName -Action {
        if ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption -Like "*Windows 10*") {

            Write-Host "Configure Windows Update for Windows 10"

            Write-Host "Disabling P2P Update downlods outside of local network"
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config -Name DODownloadMode -Type DWord -Value 1
            Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization -Name SystemSettingsDownloadMode -Type DWord -Value 3
        }
    }
}
#endRegion

Write-Host "Step 4 - Update PowerShell and PowerShell help"
#region Update PowerShell and PowerShell help
if ($SetStepNumber -eq 4) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Update PowerShell and help" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host "Updating PowerShellGet and PackageManagement modules..."
        Install-OrUpdateModule -Name PowerShellGet
        Install-OrUpdateModule -Name PackageManagement

        Write-Host "Update PowerShell and PowerShell help"
        if ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption -Like "*Windows 10*" -or (Get-CimInstance -ClassName Win32_OperatingSystem).Caption -Like "*Windows 11*") {
            Write-Host "Checking for latest PowerShell Core (pwsh)..."
            $pwshPath = Get-Command pwsh.exe -ErrorAction SilentlyContinue

            if (-not $pwshPath) {
                try {
                    Write-Host "Installing PowerShell Core (pwsh)..."
                    winget install --id Microsoft.Powershell --source winget --accept-package-agreements --accept-source-agreements
                }
                catch {
                    Write-Warning "Failed to install PowerShell Core via winget: $($_.Exception.Message)"
                }
            }
            else {
                Write-Host "PowerShell Core (pwsh) is already installed."
            }
        }

        try {
            Write-Host "Updating help for all modules..."
            Update-Help -Force -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to update PowerShell help: $($_.Exception.Message)"
        }
    }
}
#EndRegion

Write-Host "Step 5 - Set up Power settings"
#region Set up Power settings
if ($SetStepNumber -eq 5) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Set up Power settings" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host "Set up Power settings"
        powercfg.exe /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    }
}
#endRegion power settings

Write-Host "Step 6 - Local User Policy"
#region Local User Policy
if ($SetStepNumber -eq 6) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Local User Policy" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host "Local User Policy"
        Write-Host "Set the password to never expire"
        Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1

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
    }
}

#endRegion

Write-Host "Step 7 - Privacy"
#region Privacy
if ($SetStepNumber -eq 7) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Privacy" -LogPath $LogPath -FileName $FileName -Action {
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
        Get-Service DiagTrack, Dmwappushservice -ErrorAction SilentlyContinue | Stop-Service | Set-Service -StartupType Disabled
    }
}

#endRegion

Write-Host "Step 8 - Set up browser homepage to local environment"
#region Set up browser homepage to local environment
if ($SetStepNumber -eq 8) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Set up browser homepage to local environment" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host "Set up browser homepage to local environment"

        Install-OrUpdateModule -Name d365fo.tools -Import

        # Get the local D365 URL
        $d365UrlObj = Get-D365Url
        $URL = $d365UrlObj.Url

        # Set D365 Start Page (if function available)
        if ($d365UrlObj) {
            $d365UrlObj | Set-D365StartPage
        }

        try {
            # Set Microsoft Edge homepage via registry
            $edgePolicyPath = 'HKLM:\Software\Policies\Microsoft\Edge'
            $edgeUrlsPath = Join-Path $edgePolicyPath 'RestoreOnStartupURLs'
            $startupValue = 4

            if (!(Test-Path $edgePolicyPath)) {
                New-Item -Path $edgePolicyPath -Force | Out-Null
            }
            Set-ItemProperty -Path $edgePolicyPath -Name 'RestoreOnStartup' -Type DWord -Value $startupValue -Force

            if (!(Test-Path $edgeUrlsPath)) {
                New-Item -Path $edgeUrlsPath -Force | Out-Null
            }
            Set-ItemProperty -Path $edgeUrlsPath -Name '1' -Value $URL

            Write-Host "The Edge homepage has been set as: $URL"

        } catch {
            Write-Warning "Failed to set Microsoft Edge homepage: $($_.Exception.Message)"
        }

        try {
            Write-Host "Setting Management Reporter to manual startup to reduce churn and Event Log messages"
            $mrService = Get-D365Environment -FinancialReporter -ErrorAction Stop
            if ($mrService) {
                $mrService | Set-Service -StartupType Manual -ErrorAction Stop
            } else {
                Write-Host "Management Reporter service not found; skipping."
            }
        }
        catch {
            Write-Warning "Failed to set Management Reporter startup type: $($_.Exception.Message)"
        }

        # Add Windows Defender exclusions to speed up compilation
        Write-Host "Setting Windows Defender rules to speed up compilation time"
        Add-D365WindowsDefenderRules -Silent
    }
}
#endRegion
#endregion

if ((Get-ScheduledTask -TaskName "WindowsSetup-Machine" -ErrorAction SilentlyContinue)){
    Unregister-ScheduledTask -TaskName "WindowsSetup-Machine" -Confirm:$false
}

Wait-ForKeyPress
