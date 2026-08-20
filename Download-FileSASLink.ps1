<#
.SYNOPSIS
    Downloads a file from Azure Blob Storage using a SAS link.
.DESCRIPTION
    This script downloads a specified file from Azure Blob Storage using a provided SAS link and saves it to a designated destination folder.
.NOTES
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$true, HelpMessage="SAS Link for the Azure Blob Storage")]
    [string]$SASLink,
    [Parameter(Mandatory=$true, HelpMessage="Name of the file and extension to download")]
    [string]$FileName,
    [Parameter(Mandatory=$true, HelpMessage="Destination folder to save the downloaded file")]
    [string]$DestinationFolder
)

#region Variables
$CurrentPath    = $PSScriptRoot       
$AzCopyPath     = 'C:\temp\d365fo.tools\AzCopy\'
#endregion

#region Functions
<#
    .SYNOPSIS
        Installs or updates a list of PowerShell modules.

    .DESCRIPTION
        This function checks for the presence of specified PowerShell modules. If a module is already installed, it updates it to the latest version. If it is not installed, the function installs it from the PowerShell Gallery.

    .EXAMPLE
        Install-ModuleList
        Installs or updates the predefined list of PowerShell modules.

    .NOTES
        - Requires internet access to download modules from the PowerShell Gallery.
        - May require administrative privileges to install modules for all users.

    .OUTPUTS
        None. The function performs installation and updates without returning output.
#>
function Install-ModuleList{
    Process{
        $Module2Service = $('d365fo.tools')
        
        $Module2Service | ForEach-Object {
            if (Get-Module -ListAvailable -Name $_) {
                Write-Host "Updating "$_ -ForegroundColor DarkMagenta
                Write-Host "--------------------------------"
                Update-Module -Name $_ -Force
                Write-Host "Updated "$_ -ForegroundColor Green
                Write-Host ""
            } 
            else {
                Write-Host "Installing "$_ -ForegroundColor DarkMagenta
                Write-Host "--------------------------------"
                Install-Module -Name $_ -SkipPublisherCheck -Scope AllUsers
                Import-Module $_
                Write-Host "Installed "$_ -ForegroundColor Green
                Write-Host ""
            }
        }
    }
}
#endregion

[Environment]::SetEnvironmentVariable("ServiceDrive", "C:", "Machine")

Write-Host ""
Write-Host 'Install modules...' -ForegroundColor Cyan
Install-ModuleList
Write-Host ""

Write-Host 'Downloading AzCopy...' -ForegroundColor Cyan
Invoke-D365InstallAzCopy -Path (join-path $AzCopyPath "AzCopy.exe")
Write-Host "Downloaded AzCopy to $AzCopyPath" -ForegroundColor Green
Write-Host ""

Write-Host 'Downloading file from Azure Blob Storage using SAS Link...' -ForegroundColor Cyan
Invoke-D365AzCopyTransfer -SourceUri $SASLink -DestinationUri (Join-Path $DestinationFolder $FileName) -LogPath "$DestinationFolder" -ShowOriginalProgress:$true -Force:$Force 

$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null