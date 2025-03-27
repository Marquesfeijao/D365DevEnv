[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$false)]
    [int]$SetStepNumber = 0
)

#region Set up script
$InstallPath    = "C:\Temp\D365FODevEnv-Installer"
$CurrentPath    = (Get-Location).Path
$FileName       = "taskLog.txt"
$LogPath        = $CurrentPath + "\Logs\"
$AddinPath      = $InstallPath + "\Addin"
$DeployPackages = $InstallPath + "\DeployablePackages"

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

function Stop-MainProcesses {
    $MainProcesses = @("chrome", "firefox", "iexplore", "msedge", "opera", "devenv")

    $MainProcesses | ForEach-Object {
        if ((Get-Process -Name $_ -ErrorAction Ignore)) {
            Stop-Process -Name $_ -PassThru -ErrorAction Ignore -Force
        }
    }

}

function Start-StopServices {
    param (
        [Parameter(Mandatory=$true)][string]$StepProcess
    )
    $Services = @("DocumentRoutingService", "DynamicsAxBatch", "Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe", "W3SVC", "MR2012ProcessService", "aspnet_state")

    switch ($StepProcess) {
        "Start" { 
            Write-Host "*** Starting services... ***" 
    
            $Services | ForEach-Object {
                if ((Get-Service -Name $_ -ErrorAction Ignore)) {
                    Start-Service -Name $_ -ErrorAction Ignore -PassThru -Verbose
                }
            }
        
            iisreset.exe
        }
        "Stop" { 
            Write-Host "*** Stopping services... ***"
        
            $Services | ForEach-Object {
                if ((Get-Service -Name $_ -ErrorAction Ignore)) {
                    Stop-Service -Name $_ -ErrorAction Ignore -PassThru -Verbose
                }
            }
        }
    }
}

function Invoke-VSInstallExtension {
    param(
        [Parameter(Position=1)][ValidateSet('2022')][System.String]$Version,  
        [Parameter(Mandatory = $true)][string]$PackageName)

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

    If ((test-path $VSInstallDir)) {

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
        
        Write-Host "************    VSInstallDir is:  $($VSInstallDir)"
        Write-Host "************    VsixLocation is: $($VsixLocation)"
        Write-Host "************    Installing: $($PackageName)..."
        Start-Process -Filepath "$($VSInstallDir)\VSIXInstaller" -ArgumentList "/q /a $($VsixLocation)" -Wait

        Write-Host "Cleanup..."
        Remove-Item $VsixLocation -Force -Confirm:$false
    
        Write-Host "Installation of $($PackageName) complete!"
    }
}

function Install-Addin {

    Set-Location $AddinPath
    $repo = @("TrudAX/TRUDUtilsD365")

    $repo | ForEach-Object {
        $releases   = "https://api.github.com/repos/$_/releases"
        
        Write-Host Determining latest release
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $tag = (Invoke-WebRequest -Uri $releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name
    
        $files = @("InstallToVS.exe", "TRUDUtilsD365.dll", "TRUDUtilsD365.pdb")
    
        Write-Host Downloading files
        
        foreach ($file in $files) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $download = "https://github.com/$_/releases/download/$tag/$file"
            Invoke-WebRequest $download -Out $file
            Unblock-File $file
        }
    
        Start-Process "InstallToVS.exe" -Verb runAs
    }
}
#endRegion

Write-Host "Initializing script"
#region Initialize script
Start-StopServices -StepProcess "Stop"
Stop-MainProcesses
#endRegion

Write-Host "Step 9"
#region Install PowerShell modules
if ($SetStepNumber -eq 9) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "Install PowerShell modules"
        $Module2Service = $('Az','dbatools','d365fo.tools','SqlServer')

        $Module2Service | ForEach-Object {
            if (Get-Module -ListAvailable -Name $_) {
                Write-Host "Updating " + $_        
        
                try {
                    Update-Module -Name $_ -Force -Scope AllUsers -ErrorAction Stop
                    Import-Module $_    
                }
                catch {
                    <#Do this if a terminating exception happens#>
                    Write-Host "Error updating module $_"
                    Uninstall-Module -Name $_ -Force -AllVersions
                    Install-Module -Name $_ -SkipPublisherCheck -Scope AllUsers -AllowClobber -Force
                }
            } 
            else {
                Write-Host "Installing " + $_
                Install-Module -Name $_ -SkipPublisherCheck -Scope AllUsers -AllowClobber -Force
                Import-Module $_
            }
        }
        
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

Write-Host "Step 10"
#region Update Visual Studio
if ($SetStepNumber -eq 10) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "Update Visual Studio"
        dotnet nuget add source "https://api.nuget.org/v3/index.json" --name "nuget.org"
        dotnet tool update -g dotnet-vs
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
        vs update --all
        
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++
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
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "Install Visual Studio extension / Addin / Tools"

        #region Install extensions
        Invoke-VSInstallExtension -Version 2022 -PackageName 'Zhenkas.LocateInTFS'
        Invoke-VSInstallExtension -Version 2022 -PackageName 'cpmcgrath.Codealignment'
        Invoke-VSInstallExtension -Version 2022 -PackageName 'EWoodruff.VisualStudioSpellCheckerVS2022andLater'
        Invoke-VSInstallExtension -Version 2022 -PackageName 'MadsKristensen.OpeninVisualStudioCode'
        Invoke-VSInstallExtension -Version 2022 -PackageName 'MadsKristensen.TrailingWhitespace64'
        Invoke-VSInstallExtension -Version 2022 -PackageName 'ViktarKarpach.DebugAttachManager2022'
        Invoke-VSInstallExtension -Version 2022 -PackageName 'ShemeerNS.ShemeerNSExportErrorListX64'
        Invoke-VSInstallExtension -Version 2022 -PackageName 'DrHerbie.Pomodoro2022'
        Invoke-VSInstallExtension -Version 2022 -PackageName 'HuameiSoftTools.HMT20'
        Invoke-VSInstallExtension -Version 2022 -PackageName 'HolanJan.TFSSourceControlExplorerExtension-2022'
        #endregion

        #region Install Addin
        Install-Addin
        #endregion

        #region Add Addin path to DynamicsDevConfig.xml
        $documentsFolder    = Join-Path $env:USERPROFILE 'Documents'
        $xmlFilePath	    = $documentsFolder + "\Visual Studio Dynamics 365\"
        $xmlFile		    = $xmlFilePath + "\DynamicsDevConfig.xml"
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
        
        Write-Host "Installing Default Tools and Internal Dev tools"
        #region Install Default Tools and Internal Dev tools
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
#region VSCode Extensions and App support
if ($SetStepNumber -eq 12) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "VSCode Extensions"
        #region Install VSCode Extensions
        $vsCodeExtensions = @("adamwalzer.string-converter",
                              "DotJoshJohnson.xml",
                              "IBM.output-colorizer",
                              "mechatroner.rainbow-csv",
                              "ms-vscode.PowerShell",
                              "piotrgredowski.poor-mans-t-sql-formatter-pg",
                              "streetsidesoftware.code-spell-checker",
                              "ZainChen.json")

        $vsCodeExtensions | ForEach-Object {
            code --install-extension $_
        }
        #endregion

        Write-Host "VSCode App support"
        #region Install VSCode App support
        Install-D365SupportingSoftware -Name "7zip","adobereader","azure-cli","azure-data-studio","azurepowershell","dotnetcore","fiddler","git.install","googlechrome","notepadplusplus.install","powertoys","p4merge","postman","sysinternals","vscode","visualstudio-codealignment","vscode-azurerm-tools","vscode-powershell","winmerge"
        #endregion
        
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
