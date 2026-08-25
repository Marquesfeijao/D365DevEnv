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

Import-Module "$PSScriptRoot\Set-ScheduledTask.psm1" -DisableNameChecking

<#
.SYNOPSIS
    Downloads and installs the latest TRUDUtilsD365 add-in release into Visual Studio.

.DESCRIPTION
    Determines the latest GitHub release tag for the TrudAX/TRUDUtilsD365 repo, downloads its
    installer and DLL/PDB assets into $AddinPath, unblocks them, and launches InstallToVS.exe
    elevated to register the add-in with Visual Studio.

.EXAMPLE
    Install-Addin
#>
function Install-Addin {
    Process {
        #Set-Location $AddinPath
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
        
            Start-Process -FilePath (Join-Path $AddinPath "InstallToVS.exe") -WorkingDirectory $AddinPath -Verb runAs
        }
    }
}
#Install-Addin
#Set-ScheduledTask -TaskName "WindowsSetup-Machine" -StepNumber ($SetStepNumber + 1) -Description "Windows update" -ScriptToRun "WindowsSetup.ps1"
#Set-ScheduledTask -TaskName "Update_Visual_Studio" -StepNumber 12 -Description "Restart machine after Update Visual Studio" -ScriptToRun "InstallUpdateApps.ps1"

#Invoke-WithRetry -OperationName "vs CLI tool update" -ScriptBlock {
#dotnet tool uninstall --global dotnet-outdated
#dotnet tool install --global dotnet-outdated-tool
#}
dotnet tool update -g vs