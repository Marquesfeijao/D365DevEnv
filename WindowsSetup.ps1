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
    [int]$SetStepNumber = 1,

    [Parameter(Mandatory=$false)]
    [string]$RunTimestamp
)

#region Set up script
$CurrentPath    = $PSScriptRoot

if ([string]::IsNullOrEmpty($RunTimestamp)) {
    $RunTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
}
$FileName       = "taskLog_$RunTimestamp.txt"
$LogPath        = Join-Path $CurrentPath "Logs"

Import-Module "$PSScriptRoot\Modules\Set-ScheduledTask.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Modules\Install-Powershell7.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Modules\Write-Log.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Modules\Invoke-SetupStep.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Modules\Invoke-WithRetry.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Modules\Install-OrUpdateModule.psm1" -DisableNameChecking

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

        Set-ScheduledTask -TaskName "WindowsSetup-Machine" -StepNumber 1 -Description "Update the cipher" -ScriptToRun "WindowsSetup.ps1" -RunTimestamp $RunTimestamp
    }
}
#endRegion

#region Initialize
if ($SetStepNumber -eq 1) {
    Initialize-Script
}
#endregion

#region Steps to run
Write-Host ""
Write-Host ":: Executing step: 1 - Windows Preferences" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Windows Preferences
if ($SetStepNumber -eq 1) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Windows Preferences" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host ""
        Write-Host ": Set up Power settings" -ForegroundColor cyan
        #region Set up Power settings
        try {
            powercfg.exe /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        }
        catch {
            Write-Warning "Failed to set up Power settings: $($_.Exception.Message)"
        }
        #endregion

        Write-Host ""
        Write-Host ": User policy" -ForegroundColor cyan
        #region User policy
        Write-Host "*Set the password to never expire" -ForegroundColor DarkYellow
        #region Set the password to never expire
        try {
            Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1
        }
        catch {
            Write-Warning "Failed to set password to never expire: $($_.Exception.Message)"
        }
        #endregion

        Write-Host "*Disable changing the password" -ForegroundColor DarkYellow
        #region Disable changing the password
        try {
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
        catch {
            Write-Warning "Failed to disable changing the password: $($_.Exception.Message)"
        }
        #endregion
        #endregion

        Write-Host ""
        Write-Host ": Privacy" -ForegroundColor cyan
        #region Privacy
        #region Disable Bing Search Results
        try {
            Write-Host "* Disable Bing Search Results" -ForegroundColor DarkYellow
            Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name BingSearchEnabled -Type DWord -Value 0
        }
        catch {
            Write-Warning "Failed to disable Bing Search Results: $($_.Exception.Message)"
        }
        #endregion
        
        #region Settings: Accept Privacy Policy
        try {
            Write-Host "* Settings: Accept Privacy Policy" -ForegroundColor DarkYellow

            if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
                New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
            }

            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
        }
        catch {
            Write-Warning "Failed to set AcceptedPrivacyPolicy: $($_.Exception.Message)"
        }
        #endregion

        #region Input Personalization: Restrict Implicit Data Collection
        try {
            Write-Host "* Input Personalization: Restrict Implicit Data Collection" -ForegroundColor DarkYellow

            if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
                New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
            }

            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
        }
        catch {
            Write-Warning "Failed to set Input Personalization settings: $($_.Exception.Message)"
        }
        #endregion

        #region Trained Data Store: Disable Contact Harvesting
        try {
            Write-Host "* Trained Data Store: Disable Contact Harvesting" -ForegroundColor DarkYellow

            if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
                New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
            }

            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
        }
        catch {
            Write-Warning "Failed to set Trained Data Store settings: $($_.Exception.Message)"
        }
        #endregion

        #region Windows Search: Disable Cortana
        try {
            Write-Host "* Windows Search: Disable Cortana" -ForegroundColor DarkYellow

            if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
            }

            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
        }
        catch {
            Write-Warning "Failed to disable Cortana: $($_.Exception.Message)"
        }
        #endregion

        #region Windows Telemetry: Disable Data Collection
        try {
            Write-Host "* Windows Telemetry: Disable Data Collection" -ForegroundColor DarkYellow

            Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name AllowTelemetry -Type DWord -Value 0
            Get-Service DiagTrack, Dmwappushservice -ErrorAction SilentlyContinue | Stop-Service | Set-Service -StartupType Disabled
        }
        catch {
            Write-Warning "Failed to disable Windows Telemetry: $($_.Exception.Message)"
        }
        #endregion
        #endregion Privacy

        Write-Host ""
        Write-Host ": Windows Explore preferences" -ForegroundColor Cyan
        #region Windows Explore preferences
        try {
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

            Set-ItemProperty -Path $regPath -Name "HideFileExt" -Value 0 -Force
            Set-ItemProperty -Path $regPath -Name "AutoCheckSelect" -Value 1 -Force
            Set-ItemProperty -Path $regPath -Name "ShowLibraries" -Value 1 -Force
            Set-ItemProperty -Path $regPath -Name "NavPaneExpandToCurrentFolder" -Value 1 -Force
            Set-ItemProperty -Path $regPath -Name "TaskbarSmallIcons" -Value 1 -Force

            Stop-Process -Name explorer -Force
            Start-Process explorer
        }
        catch {
            Write-Warning "Failed to set Windows Explorer preferences: $($_.Exception.Message)"
        }

        #endregion

        Write-Host ""
        Write-Host ": Configuring Desktop Settings" -ForegroundColor Cyan
        #region Configuring Desktop Settings
        try {
            # Define registry paths
            $advancedPath   = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            $desktopPath    = "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop"

            # Ensure registry paths exist
            if (-not (Test-Path $desktopPath)) {
                New-Item -Path $desktopPath -Force | Out-Null
            }

            # 1. Show desktop icons (0 = show, 1 = hide)
            Write-Host "* Desktop icons enabled" -ForegroundColor DarkYellow
            Set-ItemProperty -Path $advancedPath -Name "HideIcons" -Value 0 -Force

            Write-Host "* Small icons applied" -ForegroundColor DarkYellow
            # 2. Use small icons (32 = small, 48 = medium, 96 = large, 256 = extra large)
            Set-ItemProperty -Path $desktopPath -Name "IconSize" -Value 32 -Force

            Write-Host "* Grid alignment enabled" -ForegroundColor DarkYellow
            # 3. Align icons to grid
            Set-ItemProperty -Path $desktopPath -Name "Mode" -Value 1 -Force

            # Restart Explorer to apply changes
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Process explorer
        }
        catch {
            Write-Warning "Failed to configure Desktop settings: $($_.Exception.Message)"
        }
        #endregion

        Write-Host ""
        Write-Host ": Rename C: Drive to a new name" -ForegroundColor Cyan
        #region Rename C: Drive to a new name
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
        #endregion

        Write-Host ""
        Write-Host ": Rename computer name" -ForegroundColor Cyan
        #region Rename computer name
        try {
            $newComputerName        = "Prometheus"
            $currentComputerName    = (Get-CimInstance -ClassName Win32_ComputerSystem).Name

            if ($currentComputerName -ne $newComputerName) {
                Write-Host "* Renaming computer from '$currentComputerName' to '$newComputerName'" -ForegroundColor DarkYellow
                Rename-Computer -NewName $newComputerName -Force -ErrorAction Stop

                Write-Host "* Computer name will be changed after reboot." -ForegroundColor DarkYellow
            }
            else {
                Write-Host "* Computer name is already set to '$newComputerName'. No change needed." -ForegroundColor DarkYellow
            }

            # Check if a reboot is required; if so, log completion, register the resume task, and
            # exit here since the normal post-Action logging in Invoke-SetupStep won't run.
            if (Get-WURebootStatus) {
                Write-Log -Level StepComplete -StepNum $SetStepNumber -Message "Windows Preferences" -LogPath $LogPath -FileName $FileName
                Set-ScheduledTask -TaskName "Windows-Preferences-ComputerNameChanged" -StepNumber ($SetStepNumber + 1) -Description "Windows Preferences Computer name changed" -ScriptToRun "WindowsSetup.ps1" -RunTimestamp $RunTimestamp
                Exit 0
            }
        }
        catch {
            Write-Warning "Failed to rename computer: $($_.Exception.Message)"
        }
        #endregion

    } | Out-Null

    $SetStepNumber = 2
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 1 is complete" -ForegroundColor Green

Write-Host ""
Write-Host ":: Executing step: 2 - Windows update" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Windows update
if ($SetStepNumber -eq 2) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Windows update" -LogPath $LogPath -FileName $FileName -Action {
        
        if ((Get-ScheduledTask -TaskName "Windows-Preferences-ComputerNameChanged" -ErrorAction SilentlyContinue)){
            Unregister-ScheduledTask -TaskName "Windows-Preferences-ComputerNameChanged" -Confirm:$false
        }
        
        Write-Host ""
        Write-Host ": Windows update" -ForegroundColor Cyan
        #region Windows update
        try {
            Write-Host "* NuGet package provider install" -ForegroundColor DarkYellow

            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Invoke-WithRetry -OperationName "NuGet package provider install" -LogPath $LogPath -FileName $FileName -ScriptBlock {
                    Install-PackageProvider -Name NuGet -Force -Confirm:$false -ErrorAction Stop
                }
            }
        }
        catch {
            Write-Warning "Failed to install NuGet package provider: $($_.Exception.Message)"
        }
        #endregion
        
        #region Windows Update download
        try {
            Write-Host "* Windows Update download" -ForegroundColor DarkYellow
            Install-OrUpdateModule -Name PSWindowsUpdate -Import

            Invoke-WithRetry -OperationName "Windows Update download" -LogPath $LogPath -FileName $FileName -ScriptBlock {
                Get-WindowsUpdate -Download -ErrorAction Stop
            }
        }
        catch {
            Write-Warning "Failed to download Windows updates: $($_.Exception.Message)"
        }
        #endregion

        #region Windows Update install
        try {
            Write-Host "* Windows Update install" -ForegroundColor DarkYellow
            Install-OrUpdateModule -Name PSWindowsUpdate -Import

            Invoke-WithRetry -OperationName "Windows Update install" -LogPath $LogPath -FileName $FileName -ScriptBlock {
                Get-WindowsUpdate -Install -Verbose -AcceptAll -ErrorAction Stop
            }
        }
        catch {
            Write-Warning "Failed to install Windows updates: $($_.Exception.Message)"
        }
        #endregion

        # Check if a reboot is required; if so, log completion, register the resume task, and
        # exit here since the normal post-Action logging in Invoke-SetupStep won't run.
        if (Get-WURebootStatus) {
            Write-Log -Level StepComplete -StepNum $SetStepNumber -Message "Windows update" -LogPath $LogPath -FileName $FileName
            Set-ScheduledTask -TaskName "WindowsSetup-Machine" -StepNumber ($SetStepNumber + 1) -Description "Windows update" -ScriptToRun "WindowsSetup.ps1" -RunTimestamp $RunTimestamp
            Exit 0
        }
    } | Out-Null

    $SetStepNumber = 3
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 2 is complete" -ForegroundColor Green

Write-Host ""
Write-Host ":: Executing step: 3 - Update PowerShell and PowerShell help" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Update PowerShell and PowerShell help
if ($SetStepNumber -eq 3) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Update PowerShell and help" -LogPath $LogPath -FileName $FileName -Action {
        
        if ((Get-ScheduledTask -TaskName "WindowsSetup-Machine" -ErrorAction SilentlyContinue)){
            Unregister-ScheduledTask -TaskName "WindowsSetup-Machine" -Confirm:$false
        }
        
        Write-Host ""
        Write-Host ": Updating PowerShellGet and PackageManagement modules" -ForegroundColor Cyan
        #region Update PowerShellGet and PackageManagement modules
        try {
            Write-Host "* Installing/Updating PowerShellGet and PackageManagement modules" -ForegroundColor DarkYellow
            Invoke-WithRetry -OperationName "Update PowerShellGet and PackageManagement modules" -LogPath $LogPath -FileName $FileName -ScriptBlock {
                Install-OrUpdateModule -Name PowerShellGet
                Install-OrUpdateModule -Name PackageManagement
            }
            Install-OrUpdateModule -Name PowerShellGet
            Install-OrUpdateModule -Name PackageManagement
        }
        catch {
            Write-Warning "Failed to update PowerShellGet or PackageManagement modules: $($_.Exception.Message)"
        }
        #endregion

        #region Update PowerShell and PowerShell help
        try {
            Write-Host "* Updating PowerShell and PowerShell help" -ForegroundColor DarkYellow
            Invoke-WithRetry -OperationName "Update PowerShell and PowerShell help" -LogPath $LogPath -FileName $FileName -ScriptBlock {
                Install-OrUpdateModule -Name PowerShellGet
                Install-OrUpdateModule -Name PackageManagement
                Update-Help -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Warning "Failed to update PowerShell or PowerShell help: $($_.Exception.Message)"
        }
        #endregion
        
        #region Update help for all modules
        try {
            Write-Host "* Updating help for all modules" -ForegroundColor DarkYellow
            Invoke-WithRetry -OperationName "Update help for all modules" -LogPath $LogPath -FileName $FileName -ScriptBlock {
                Update-Help -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Warning "Failed to update PowerShell help: $($_.Exception.Message)"
        }
        #endregion
    } | Out-Null

    $SetStepNumber = 4
}
#EndRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 3 is complete" -ForegroundColor Green

Write-Host ""
Write-Host ":: Executing step: 4 - Set up Nuget" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Set up Nuget
if ($SetStepNumber -eq 4) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Set up Nuget" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host ""
        Write-Host ": Set up Nuget" -ForegroundColor Cyan
        #region Set up Nuget
        try {
            # Update the dotnet-install script to ensure we have the latest version for installing/updating .NET SDKs
            Invoke-WithRetry -OperationName "vs CLI tool update" -LogPath $LogPath -FileName $FileName -ScriptBlock {
                Invoke-WebRequest -Uri "https://builds.dotnet.microsoft.com/dotnet/scripts/v1/dotnet-install.ps1" -OutFile "dotnet-install.ps1"

                .\dotnet-install.ps1 -InstallDir "$env:USERPROFILE\.dotnet" -NoPath -Verbose

                try {
                    dotnet tool install --global dotnet-outdated-tool
                }
                catch {
                    Write-Host "dotnet-outdated-tool is already installed. Attempting to update..."
                    dotnet tool update --global dotnet-outdated-tool
                }
            }

            try {
                Invoke-WithRetry -OperationName "dotnet nuget source setup" -LogPath $LogPath -FileName $FileName -ScriptBlock {
                    if (-not (dotnet nuget list source | Select-String -Pattern "nuget.org")) {
                        dotnet nuget add source "https://api.nuget.org/v3/index.json" --name "nuget.org"
                    }
                }
            }
            catch {
                Write-Warning "Failed to set up NuGet source: $($_.Exception.Message)"
            }

            try {
                Invoke-WithRetry -OperationName "dotnet-vs tool install/update" -LogPath $LogPath -FileName $FileName -ScriptBlock {
                    if (-not (dotnet tool list -g | Select-String -Pattern "^dotnet-vs\s")) {
                        dotnet tool install -g dotnet-vs
                    } else {
                        dotnet tool update -g dotnet-vs
                    }
                }
            }
            catch {
                Write-Warning "Failed to install/update dotnet-vs tool: $($_.Exception.Message)"
            }
        }
        catch {
            Write-Warning "Failed to set up Nuget: $($_.Exception.Message)"
        }
        #endregion

        $machinePath    = [System.Environment]::GetEnvironmentVariable("Path","Machine")
        $userPath       = [System.Environment]::GetEnvironmentVariable("Path","User")
        $env:Path       = "$machinePath;$userPath"
    } | Out-Null

    $SetStepNumber = 5
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 4 is complete" -ForegroundColor Green
#endregion

Write-Host ""
Write-Host "The installation setup is completed. Press any key to exit." -ForegroundColor Green

Wait-ForKeyPress
