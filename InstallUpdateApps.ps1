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
Import-Module (Join-Path $PSScriptRoot "Set-ScheduledTask.psm1") -DisableNameChecking
#endRegion

#region Set up script
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Force -Path $LogPath
}

if (!(Test-Path "$LogPath\$FileName")) {
    New-Item -Path "$LogPath\$FileName" -ItemType File -Force
}

if (!(test-path $AddinPath)) {
    New-Item -ItemType Directory -Force -Path $AddinPath
}
else {
    Get-ChildItem $AddinPath -Recurse | Remove-Item -Force -Confirm:$false
}

if (!(test-path $DeployPackages)) {
    New-Item -ItemType Directory -Force -Path $DeployPackages
}

if ($SetStepNumber -eq 0) {
    $SetStepNumber = 9
} elseif ($SetStepNumber -notin 9..12) {
    Write-Host "Please enter a valid step number between 9 and 12"
    Exit
}
#endRegion

#region Functions
function Write-Log {
    param (
        [Parameter(Mandatory=$true)][string]$StepProcess,
        [Parameter(Mandatory=$true)][int]$StepNum,
        [Parameter(Mandatory=$true)][string]$PathLog,
        [Parameter(Mandatory=$true)][string]$FileName
    )

    Process {
        $StepExecution = ""
    
        try {
            switch ($StepProcess) {
                "StepStart"     { $StepExecution = "Step $StepNum start" }
                "StepComplete"  { $StepExecution = "Step $StepNum complete" }
                "StepError"     { $StepExecution = "Step $StepNum not complete" }
                default         { $StepExecution = "Unknown step process" }
            }
    
            Write-Output $StepExecution | Out-File (Join-Path "$PathLog" "$FileName") -Append -ErrorAction Stop
        }
        catch {
            Write-Host "Failed to write log: $($_.Exception.Message)"
        }
    }
}

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
            Where-Object { $_.class -eq 'install-button-container' } |
            Select-Object -ExpandProperty href
    
            if (-Not $anchor) {
                Write-Error "Could not find download anchor tag on the Visual Studio Extensions page"
                Exit 1
            }
            
            Write-Host "Anchor is $($anchor)"
            $href = "$($baseProtocol)//$($baseHostName)$($anchor)"
            Write-Host "Href is $($href)"
            Invoke-WebRequest $href -OutFile $VsixLocation -WebSession $session
        
            if (-Not (Test-Path $VsixLocation)) {
                Write-Error "Downloaded VSIX file could not be located"
                Exit 1
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

function Install-Addin {
    Process {
        Set-Location $AddinPath
        $repo = @("TrudAX/TRUDUtilsD365")
    
        $repo | ForEach-Object {
            $releases   = "https://api.github.com/repos/$_/releases"
            
            Write-Host ""
            Write-Host "Determining latest release for repo $_" -ForegroundColor Green
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $tag = (Invoke-WebRequest -Uri $releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name
        
            $files = @("InstallToVS.exe", "TRUDUtilsD365.dll", "TRUDUtilsD365.pdb")
            
            Write-Host ""
            Write-Host "Downloading files for repo $_" -ForegroundColor Cyan
            
            foreach ($file in $files) {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
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

Write-Host "Step 9"
#region Install PowerShell modules
if ($SetStepNumber -eq 9) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host ""
        Write-Host "Install PowerShell modules" -ForegroundColor Green
        $Module2Service = @('Az','dbatools','d365fo.tools','SqlServer')

        foreach ($mod in $Module2Service) {
            try {
                $installed = Get-Module -ListAvailable -Name $mod
                if ($installed) {
                    # Check if module is up-to-date
                    $gallery        = Find-Module -Name $mod -ErrorAction SilentlyContinue
                    $currentVersion = ($installed | Sort-Object Version -Descending | Select-Object -First 1).Version
                    
                    if ($gallery -and $gallery.Version -gt $currentVersion) {
                        Write-Host ""
                        Write-Host "Updating module $mod from $currentVersion to $($gallery.Version)" -ForegroundColor Cyan
                        Update-Module -Name $mod -Force -Scope AllUsers -ErrorAction Stop
                        Write-Host
                    } else {
                        Write-Host "Module $mod is up-to-date (version $currentVersion)"
                    }
                    
                    Import-Module -Name $mod -ErrorAction Stop
                } else {
                    Write-Host ""
                    Write-Host "Installing module $mod"
                    Install-Module -Name $mod -SkipPublisherCheck -Scope AllUsers -AllowClobber -Force -ErrorAction Stop
                    Import-Module -Name $mod -ErrorAction Stop
                    Write-Host "Installed module $mod"
                }
            } catch {
                Write-Warning "Failed to process module $mod $($_.Exception.Message)"
            }
        }
        
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 9
        Exit
    }
}
#endRegion

Write-Host "Step 10"
#region Update Visual Studio
if ($SetStepNumber -eq 10) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        Write-Host ""  
        Write-Host "Update Visual Studio" -ForegroundColor Green
        dotnet nuget add source "https://api.nuget.org/v3/index.json" --name "nuget.org"
        dotnet tool update -g dotnet-vs
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
        vs update --all
        
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++

        Set-ScheduledTask -TaskName "D365DevEnv: Update Visual Studio" -StepNumber $SetStepNumber -Description "Restart machine after Update Visual Studio" -ScriptToRun "InstallUpdateApps.ps1"
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 10
        Exit
    }
}
#endRegion

Write-Host "Step 11"
#region Install Visual Studio extension / Addin / Tools
if ($SetStepNumber -eq 11) {

        Write-Log -StepProcess "StepStart" -StepNum $1 -PathLog $LogPath -FileName $FileName

        Write-Host ""
        Write-Host "Install Visual Studio extension / Addin / Tools" -ForegroundColor Green

        #region Install extensions
        $VSInstallExtensions = @('Zhenkas.LocateInTFS'
                                ,'SIBA.Cobalt2Theme'
                                ,'cpmcgrath.Codealignment'
                                ,'EWoodruff.VisualStudioSpellCheckerVS2022andLater'
                                ,'MadsKristensen.OpeninVisualStudioCode'
                                ,'MadsKristensen.TrailingWhitespace64'
                                ,'ViktarKarpach.DebugAttachManager2022'
                                ,'ShemeerNS.ShemeerNSExportErrorListX64'
                                ,'DrHerbie.Pomodoro2022'
                                ,'HuameiSoftTools.HMT20'
                                ,'HolanJan.TFSSourceControlExplorerExtension-2022'
                                ,'sourcegraph.cody-vs'
                                ,'deadlydog.DiffAllFilesforVS2022'
                                ,'unthrottled.dokithemevisualstudio'
                                ,'ProBITools.MicrosoftRdlcReportDesignerforVisualStudio2022'
                                ,'KristofferHopland.MonokaiTheme'
                                ,'marketplace.ODataConnectedService2022'
                                ,'NikolayBalakin.Outputenhancer'
                                ,'ProjectReunion.MicrosoftSingleProjectMSIXPackagingToolsDev17'
                                ,'jefferson-pires.VisualChatGPTStudio'
                                ,'idex.vsthemepack'
                                ,'MadsKristensen.WinterIsComing'
                                ,'KenCross.VSHistory2022'
                                ,'TeamXavalon.XAMLStyler2022'
        )

        $VSInstallExtensions | ForEach-Object {
            try {
                Write-Host ""
                Write-Host "Installing extension: $_" -ForegroundColor DarkMagenta
                Invoke-VSInstallExtension -Version 2022 -PackageName $_
                Write-Host "Installed extension: $_" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to install extension $_ : $($_.Exception.Message)"
                Write-Host ""
            }
        }
        #endregion

    try {
        #region Install Addin
        Install-Addin
        #endregion

        #region Add Addin path to DynamicsDevConfig.xml
        $documentsFolder    = Join-Path $env:USERPROFILE 'Documents'
        $xmlFilePath	    = Join-Path $documentsFolder "Visual Studio Dynamics 365"
        $xmlFile		    = Join-Path $xmlFilePath "DynamicsDevConfig.xml"
        $valueToCheck       = $AddinPath

        if (!(test-path $xmlFilePath)) {
            New-Item -ItemType Directory -Force -Path $xmlFilePath
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
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 11
        Exit
    }
}
#endRegion

Write-Host "Step 12"
#region Install Apps and VSCode Extensions
if ($SetStepNumber -eq 12) {
    
    Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
    
    Write-Host ""
    Write-Host "Install Apps and VSCode Extensions" -ForegroundColor Green

    #region Install Chocolatey apps
    Write-Host ""
    Write-Host "Install Apps using chocolatey" -ForegroundColor Cyan
    
    $ChocolateyApps = @("7zip","adobereader","azure-cli","azurepowershell",
                        "dotnetcore","fiddler","git.install","googlechrome","notepadplusplus.install",
                        "powertoys","p4merge","postman","sysinternals","vscode","winmerge","WinDirStat","winrar")
    
                        
    $ChocolateyApps | ForEach-Object {
        Write-Host ""
        Write-Host "Installing: $_" -ForegroundColor DarkMagenta

        try {
            Install-D365SupportingSoftware -Name $_ -ErrorAction Ignore
            Write-Host "Installed: $_" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to install supporting software: $($_.Exception.Message)"
        }
    }

    #endregion

    #region Install VSCode Extensions
    # Write-Host "VSCode Extensions" -ForegroundColor Cyan

    # try {
    #     $vsCodeExtensions = @("adamwalzer.string-converter",
    #                             "DotJoshJohnson.xml",
    #                             "IBM.output-colorizer",
    #                             "mechatroner.rainbow-csv",
    #                             "ms-vscode.PowerShell",
    #                             "piotrgredowski.poor-mans-t-sql-formatter-pg",
    #                             "streetsidesoftware.code-spell-checker",
    #                             "ZainChen.json")

    #     $vsCodeExtensions | ForEach-Object {
    #     code --install-extension $_
    #     }
    # }
    # catch {
    #     Write-Warning "Failed to install VSCode extensions: $($_.Exception.Message)"
    # }
    #endregion
try {
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
                            
        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 12
        Exit
    }
}
#endRegion

if ((Get-ScheduledTask -TaskName "D365DevEnv: Update Visual Studio" -ErrorAction SilentlyContinue)){
    Unregister-ScheduledTask -TaskName "D365DevEnv: Update Visual Studio" -Confirm:$false
}

$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null