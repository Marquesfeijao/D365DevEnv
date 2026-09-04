<#
.SYNOPSIS
    Installs and updates essential applications, PowerShell modules, Visual Studio extensions, and supporting tools for D365DevEnv.
.DESCRIPTION
    This script automates the setup and update process for a D365 development environment. It performs:
      - Directory and log initialization
      - Stopping main processes and services
      - Installation and update of PowerShell modules
      - Visual Studio update and extension installation
      - Addin installation and configuration
      - Installation of supporting software and VSCode extensions
    The script is step-driven via the $SetStepNumber parameter, allowing granular execution of setup stages.
.PARAMETER SetStepNumber
    The step number to execute (9-12). Defaults to 9 if not specified.
.NOTES
    Author: Marquesfeijao
    Repository: D365DevEnv
    Last updated: July 2025
.EXAMPLE
    Run this script in PowerShell to perform all setup steps:
        pwsh.exe -NoProfile -File InstallUpdateApps.ps1
    Run a specific step:
        pwsh.exe -NoProfile -File InstallUpdateApps.ps1 -SetStepNumber 10
#>
[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$false)]
    [int]$SetStepNumber = 0
)
#region Variables
$CurrentPath    = $PSScriptRoot
$FileName       = "taskLog.txt"
$LogPath        = Join-Path $CurrentPath "Logs"
$AddinPath      = Join-Path $CurrentPath "Addin"
$DeployPackages = Join-Path $CurrentPath "DeployablePackages"

$StartStopServices = (Join-Path $CurrentPath "StartStopServices.ps1")
Import-Module (Join-Path $PSScriptRoot "Modules\Set-ScheduledTask.psm1") -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot "Modules\Write-Log.psm1") -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot "Modules\Invoke-SetupStep.psm1") -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot "Modules\Invoke-WithRetry.psm1") -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot "Modules\Install-OrUpdateModule.psm1") -DisableNameChecking
#endRegion

#region Set up script
try {
    Initialize-WorkDirectory -Path $LogPath

    if (!(Test-Path "$LogPath\$FileName")) {
        New-Item -Path "$LogPath\$FileName" -ItemType File -Force | Out-Null
    }

    Initialize-WorkDirectory -Path $AddinPath -ClearIfExists
    Initialize-WorkDirectory -Path $DeployPackages
}
catch {
    Write-Host "Failed to initialize working directories: $($_.Exception.Message)"
    Exit 3
}

Set-TlsSecurityProtocol

$SetStepNumber = Confirm-StepNumber -RequestedStep $SetStepNumber -DefaultStep 9 -MinStep 9 -MaxStep 12
#endRegion

#region Functions
<#
.SYNOPSIS
    Stops common browser and Visual Studio processes if they are running.

.DESCRIPTION
    Iterates over a fixed list of process names (chrome, firefox, iexplore, msedge, opera,
    devenv) and force-stops any that are currently running, so they don't lock files or hold
    ports needed by the subsequent install/update steps.

.EXAMPLE
    Stop-MainProcesses
#>
function Stop-MainProcesses {
    Process {
        Write-Host""
        Write-Host "Stopping main processes if running..." -ForegroundColor Green
        $MainProcesses = @("chrome", "firefox", "iexplore", "msedge", "opera", "devenv")

        $MainProcesses | ForEach-Object {
            if ((Get-Process -Name $_ -ErrorAction Ignore)) {
                Stop-Process -Name $_ -PassThru -ErrorAction Ignore -Force
            }
        }
    }
}

<#
.SYNOPSIS
    Downloads a Visual Studio Marketplace extension and installs it into a local VS install.

.DESCRIPTION
    Looks up the given Visual Studio version's install directory, scrapes the extension's
    Marketplace page for its VSIX download link, downloads the VSIX to a temporary file, runs
    VSIXInstaller against it in quiet mode, and deletes the temporary file afterward. Only
    proceeds if the resolved VS install directory exists on disk.

.PARAMETER Version
    The Visual Studio version to install the extension into. Currently only "2022" is accepted.

.PARAMETER PackageName
    The Marketplace item name of the extension to install (the itemName query value from its
    Marketplace URL).

.EXAMPLE
    Invoke-VSInstallExtension -Version 2022 -PackageName "SomePublisher.SomeExtension"
#>
function Invoke-VSInstallExtension {
    param (
        [Parameter(Position=1)][ValidateSet('2022')][System.String]$Version,
        [Parameter(Mandatory = $true)][string]$PackageName
    )

    Process {
        $ErrorActionPreference = "Stop"

        $baseProtocol	= "https:"
        $baseHostName	= "marketplace.visualstudio.com"
        $Uri			= "$($baseProtocol)//$($baseHostName)/items?itemName=$($PackageName)"
        $VsixLocation	= "$($env:Temp)\$([guid]::NewGuid()).vsix"

        switch ($Version) {
            '2019' {
                $VSInstallDir = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service"
            }
            '2022' {
                $VSInstallDir = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\"
            }
        }

        if ((test-path $VSInstallDir)) {

            Write-Host "Grabbing VSIX extension at $($Uri)"
            $HTML = Invoke-WebRequest -Uri $Uri -UseBasicParsing -SessionVariable session

            Write-Host "Attempting to download $($PackageName)..."
            $anchor = $HTML.Links |
            Where-Object { $_.class -eq "install-button-container install-btn" } |
            Select-Object -ExpandProperty href

            # if (-Not $anchor) {
            #     throw "Could not find download anchor tag on the Visual Studio Extensions page for $($PackageName)"
            # }

            Write-Host "Anchor is $($anchor)"
            $href = "$($baseProtocol)//$($baseHostName)$($anchor)"
            Write-Host "Href is $($href)"
            Invoke-WebRequest $href -OutFile $VsixLocation -WebSession $session

            if (-Not (Test-Path $VsixLocation)) {
                throw "Downloaded VSIX file could not be located for $($PackageName)"
            }

            Write-Host "- VSInstallDir  : $($VSInstallDir)"
            Write-Host "- VsixLocation  : $($VsixLocation)"
            Write-Host "- Installing    : $($PackageName)..."
            Start-Process -Filepath "$($VSInstallDir)\VSIXInstaller" -ArgumentList "/q /a $($VsixLocation)" -Wait

            Write-Host "Cleanup..."
            Remove-Item $VsixLocation -Force -Confirm:$false

            Write-Host "Installation of $($PackageName) complete!"
        }
    }
}

<#
.SYNOPSIS
    Downloads and installs the latest TRUDUtilsD365 add-in release into Visual Studio.

.DESCRIPTION
    Determines the latest GitHub release tag for the TrudAX/TRUDUtilsD365 repo, downloads its
    installer and DLL/PDB assets into $AddinPath, unblocks them, and launches InstallToVS.exe
    elevated to register the add-in with Visual Studio.

.EXAMPLE
    Install-Addin

.NOTES
    Requires network access to api.github.com and github.com, and elevation (UAC prompt) to run
    the installer.
#>
function Install-Addin {
    Process {
        Set-Location $AddinPath
        $repo = @("TrudAX/TRUDUtilsD365")

        $repo | ForEach-Object {
            $releases   = "https://api.github.com/repos/$_/releases"

            Write-Host ""
            Write-Host "Determining latest release for repo $_" -ForegroundColor Green
            $tag = (Invoke-WebRequest -Uri $releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name

            $files = @("InstallToVS.exe", "TRUDUtilsD365.dll", "TRUDUtilsD365.pdb")

            Write-Host ""
            Write-Host "Downloading files for repo $_" -ForegroundColor Cyan

            foreach ($file in $files) {
                $download = "https://github.com/$_/releases/download/$tag/$file"
                Invoke-WebRequest $download -OutFile (join-path $AddinPath $file)
                Unblock-File (join-path $AddinPath $file)
            }

            Start-Process -FilePath (Join-Path $AddinPath "InstallToVS.exe") -Verb runAs
        }
    }
}
#endRegion

Write-Host ""
Write-Host "Initializing script" -ForegroundColor Green
#region Initialize script
pwsh.exe -NoProfile -File $StartStopServices -ServiceStatus "Stop"
Stop-MainProcesses
#endRegion

Write-Host ""
Write-Host ":: Executing step: 9" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Install PowerShell modules
if ($SetStepNumber -eq 9) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Install PowerShell modules" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host ""
        Write-Host "Install PowerShell modules" -ForegroundColor Cyan
        $Module2Service = @('Az','dbatools','d365fo.tools','SqlServer')

        foreach ($mod in $Module2Service) {
            try {
                Install-OrUpdateModule -Name $mod -Import
            } catch {
                Write-Warning "Failed to process module $mod $($_.Exception.Message)"
            }
        }
    }

    $SetStepNumber = 9
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 9 is completed" -ForegroundColor Green

Write-Host ""
Write-Host ":: Executing step: 10" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Install Apps and VSCode Extensions
if ($SetStepNumber -eq 10) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Install Apps and VSCode Extensions" -LogPath $LogPath -FileName $FileName -Action {
        #region Install Chocolatey apps
        Write-Host ""
        Write-Host "Install Apps using chocolatey" -ForegroundColor Cyan

        $ChocolateyApps = @("7zip"
                            ,"adobereader"
                            ,"azure-cli"
                            ,"azurepowershell"
                            ,"dotnetcore"
                            ,"fiddler"
                            ,"git.install"
                            ,"googlechrome"
                            ,"notepadplusplus.install"
                            ,"powertoys"
                            ,"p4merge"
                            ,"postman"
                            ,"sysinternals"
                            ,"vscode"
                            ,"winmerge"
                            ,"WinDirStat"
                            ,"winrar")

        $ChocolateyApps | ForEach-Object {
            try {
                Write-Host ""
                Write-Host "Installing: $_" -ForegroundColor DarkMagenta

                Install-D365SupportingSoftware -Name $_ -ErrorAction Ignore
                Write-Host "Installed: $_" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to install supporting software: $($_.Exception.Message)"
            }
        }
        #endregion

        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Set-ScheduledTask -TaskName "D365DevEnv-RefreshInstalledAndUpdatedApps" -StepNumber ($SetStepNumber + 1) -Description "Restart machine after installation of apps" -ScriptToRun "InstallUpdateApps.ps1"
        Exit 0
    }

    $SetStepNumber = 11
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 10 is completed" -ForegroundColor Green

Write-Host ""
Write-Host ":: Executing step: 11" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Update Visual Studio
if ($SetStepNumber -eq 11) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Update Visual Studio" -LogPath $LogPath -FileName $FileName -Action {

        if ((Get-ScheduledTask -TaskName "D365DevEnv-RefreshInstalledAndUpdatedApps" -ErrorAction SilentlyContinue)){
            Unregister-ScheduledTask -TaskName "D365DevEnv-RefreshInstalledAndUpdatedApps" -Confirm:$false
        }

        Write-Host ""
        Write-Host "Update Visual Studio" -ForegroundColor Green

        # Update the new Visual Studio CLI tool (replaces dotnet-vs)
        Invoke-WithRetry -OperationName "vs CLI tool update" -ScriptBlock {
            dotnet tool update -g vs
        }

        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

        # Update all Visual Studio installations
        vs update --all

        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Set-ScheduledTask -TaskName "D365DevEnv-Update_Visual_Studio" -StepNumber ($SetStepNumber + 1) -Description "Restart machine after Update Visual Studio" -ScriptToRun "InstallUpdateApps.ps1"
        Exit 0
    }

    $SetStepNumber = 12
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 11 is completed" -ForegroundColor Green

Write-Host ""
Write-Host ":: Executing step: 12" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Install Visual Studio extension / Addin / Tools
if ($SetStepNumber -eq 12) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Install Visual Studio extension / Addin / Tools" -LogPath $LogPath -FileName $FileName -Action {

        if ((Get-ScheduledTask -TaskName "D365DevEnv-Update_Visual_Studio" -ErrorAction SilentlyContinue)){
            Unregister-ScheduledTask -TaskName "D365DevEnv-Update_Visual_Studio" -Confirm:$false
        }

        Write-Host ""
        Write-Host "Install Visual Studio extension / Addin / Tools" -ForegroundColor Green

        #region Install extensions
        $VSInstallExtensions = @('AmichaiMantinband.amikodark'
                                ,'cpmcgrath.Codealignment'
                                ,'deadlydog.DiffAllFilesforVS2022'
                                ,'dliedke.ClaudeCodeExtension'
                                ,'DrHerbie.Pomodoro2022'
                                ,'EWoodruff.VisualStudioSpellCheckerVS2022andLater'
                                ,'github-copilot-azure.GitHubCopilotForAzure2022'
                                ,'HolanJan.TFSSourceControlExplorerExtension-2022'
                                ,'HuameiSoftTools.HMT20'
                                ,'idex.vsthemepack'
                                ,'jefferson-pires.VisualChatGPTStudio'
                                ,'KenCross.VSHistory2022'
                                ,'KingswaySoft.SSISIntegrationToolkitforMicrosoftDynamics365'
                                ,'KristofferHopland.MonokaiTheme'
                                ,'MadsKristensen.ClearMEFComponentCache'
                                ,'MadsKristensen.ExtensibilityEssentials2022'
                                ,'MadsKristensen.ExtensibilityItemTemplates2022'
                                ,'MadsKristensen.ExtensibilityMargin'
                                ,'MadsKristensen.ImageManifestTools64'
                                ,'MadsKristensen.insertguid'
                                ,'MadsKristensen.KnownMonikersExplorer2022'
                                ,'MadsKristensen.OpeninVisualStudioCode'
                                ,'MadsKristensen.PkgdefLanguage'
                                ,'MadsKristensen.TrailingWhitespace64'
                                ,'MadsKristensen.VSCodeThemeConverter'
                                ,'MadsKristensen.VsctIntelliSense2022'
                                ,'MadsKristensen.VsixSynchronizer64'
                                ,'MadsKristensen.VSThemeColors2022'
                                ,'MadsKristensen.WinterIsComing'
                                ,'marketplace.ODataConnectedService2022'
                                ,'microsoft-IsvExpTools.PowerPlatformToolsVS2022'
                                ,'NikolayBalakin.Outputenhancer'
                                ,'ProBITools.MicrosoftRdlcReportDesignerforVisualStudio2022'
                                ,'ProjectReunion.MicrosoftSingleProjectMSIXPackagingToolsDev17'
                                ,'RamiAbughazaleh.TFSSourceControlExplorerExtension-2026'
                                ,'SharpDevelopTeam.ILSpy2022'
                                ,'ShemeerNS.ShemeerNSExportErrorListX64'
                                ,'sourcegraph.cody-vs'
                                ,'TeamXavalon.XAMLStyler2022'
                                ,'unthrottled.dokithemevisualstudio'
                                ,'ViktarKarpach.DebugAttachManager2022'
                                ,'VisualStudioClient.MicrosoftVisualStudio2022InstallerProjects'
                                ,'Zhenkas.LocateInTFS'
        )

        $VSInstallExtensions | ForEach-Object {
            try {
                Write-Host ""
                Write-Host "Installing extension: $_" -ForegroundColor DarkMagenta
                Invoke-WithRetry -OperationName "VS extension $_ install" -ScriptBlock {
                    Invoke-VSInstallExtension -Version 2022 -PackageName $_
                }
                
                Write-Host "Installed extension: $_" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to install extension $_ : $($_.Exception.Message)"
                Write-Host ""
            }
        }
        #endregion

        #region Install Addin
        Invoke-WithRetry -OperationName "Install-Addin" -ScriptBlock {
            Install-Addin
        }
        #endregion

        #region Add Addin path to DynamicsDevConfig.xml
        $documentsFolder    = Join-Path $env:USERPROFILE 'Documents'
        $xmlFilePath	    = Join-Path $documentsFolder "Visual Studio Dynamics 365"
        $xmlFile		    = Join-Path $xmlFilePath "DynamicsDevConfig.xml"
        $valueToCheck       = $AddinPath

        if (!(test-path $xmlFilePath)) {
            New-Item -ItemType Directory -Force -Path $xmlFilePath | Out-Null
        }

        if ((test-path $xmlFilePath) -and (test-path $xmlFile)) {
            # Load the XML file
            [xml]$xml = Get-Content -Path $xmlFile

            # Check if the value exists
            if (-not ($xml.DynamicsDevConfig.AddInPaths.string -contains $valueToCheck)) {
                # Value doesn't exist, add it
                $newElement             = $xml.CreateElement("d2p1", "string", "http://schemas.microsoft.com/2003/10/Serialization/Arrays")
                $newElement.InnerText   = $valueToCheck

                $xml.DynamicsDevConfig.AddInPaths.AppendChild($newElement)

                # Save the modified XML back to a file
                $xml.Save($xmlFile)
                Write-Host "Element added successfully."
            }
        }
        #endregion

        #region Install Default Tools and Internal Dev tools
        Write-Host ""
        Write-Host "Installing Default Tools and Internal Dev tools" -ForegroundColor Cyan
        $VSInstallDir = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service"

        if ((test-path $DeployPackages)) {
            Get-ChildItem "$DeployPackages" -Include "*.vsix" -Exclude "*.17.0.vsix" -Recurse | ForEach-Object {
                Write-Host "installing: $_"
                Split-Path -Path $VSInstallDir -Leaf -Resolve
                Start-Process -Filepath "$($VSInstallDir)\VSIXInstaller" -ArgumentList "/q /a $_" -Wait
            }

            $VSInstallDir = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\"

            Get-ChildItem "$DeployPackages" -Include "*.17.0.vsix" -Recurse | ForEach-Object {
                Write-Host "installing: $_"
                Split-Path -Path $VSInstallDir -Leaf -Resolve
                Start-Process -Filepath "$($VSInstallDir)\VSIXInstaller" -ArgumentList "/q /a $_" -Wait
            }
        }
        #endregion

        Set-Location $CurrentPath
    }

    $SetStepNumber = 13
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 12 is completed" -ForegroundColor Green

Write-Host ""
Write-Host "The installation setup is completed. Press any key to exit." -ForegroundColor Green

Wait-ForKeyPress
