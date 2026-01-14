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
    [Parameter(Mandatory=$true, HelpMessage="Name of the file to download")]
    [string]$FileName,
    [Parameter(Mandatory=$true, HelpMessage="Destination folder to save the downloaded file")]
    [string]$DestinationFolder
)

Write-Host 'Downloading file from Azure Blob Storage using SAS Link...' -ForegroundColor Cyan
Invoke-D365AzCopyTransfer -SourceUri $SASLink -DestinationUri "$DestinationFolder\$FileName" -LogPath "$DestinationFolder" -ShowOriginalProgress:$true -Force:$Force 

$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null