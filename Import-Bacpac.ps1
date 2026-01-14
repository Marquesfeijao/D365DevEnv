<#
.SYNOPSIS
    Imports a bacpac file into a new SQL database for Dynamics 365 Finance and Operations.
.DESCRIPTION
    This script imports a specified bacpac file into a new SQL database. It includes steps to
    install necessary PowerShell modules, adjust SQL Server memory settings for optimal performance,
    and manage Dynamics 365 services during the import process.
.PARAMETER BCPFilePath
    The full path to the directory containing the bacpac file.
.PARAMETER BCPFileName
    The name of the bacpac file to import.
.PARAMETER NewDBName
    The name of the new database to be created after the import.
.NOTES
    This script requires the dbatools PowerShell module and appropriate permissions to manage SQL Server and Dynamics 365 services.
#>
[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$true, HelpMessage="Full path to the bacpac file")]
    [string]$BCPFilePath,
    [Parameter(Mandatory=$true, HelpMessage="Bacpac file to import")]
    [string]$BCPFileName,
    [Parameter(Mandatory=$true, HelpMessage="Name of the new database after import")]
    [string]$NewDBName
)

#region Variables
$CurrentPath            = $PSScriptRoot                                         # Current script path
$D365FoInstance         = "."                                                   # SQL Instance name
$BCPFile                = (Join-Path $BCPFilePath $BCPFileName)                 # Full path to bacpac file
$BCPModelName           = (Join-Path $BCPFilePath "BCPModel.xml")               # Original model file
$BCPModelName_Updated   = (Join-Path $BCPFilePath "BCPModel_Updated.xml")       # Updated model file
$LogRestore             = (Join-Path $BCPFilePath "DBRestore.txt")              # Log file for restore operations
$FileStartStop          = (Join-Path $CurrentPath "StartStopServices.ps1")      # Script to start/stop D365Fo services
$RepairScript           = (Join-Path $CurrentPath "SimpleKillConnection.json")  # Script used to repair the model file

# Number of logical processors on the server, this will be used during import to define the max degree of parallelism
$NumLogicalProcessors   = (Get-WmiObject -Class Win32_ComputerSystem).NumberOfLogicalProcessors 
#endregion Variables

#Region Functions
<#
    .SYNOPSIS
        Configures the maximum memory allocation for SQL Server based on a percentage of total system memory.

    .DESCRIPTION
        Sets the SQL Server maximum memory setting to a specified percentage of the total physical memory available on the computer. This function retrieves the total system memory, calculates the allocation based on the provided factor, and applies the configuration to the specified SQL Server instance.

    .PARAMETER factorPercent
        Specifies the percentage of total physical memory to allocate to SQL Server. This value should be expressed as a decimal (e.g., 0.80 for 80%). This parameter is mandatory.

    .EXAMPLE
        Set-DBMemory -factorPercent 0.80
        Allocates 80% of the total physical memory to the SQL Server instance stored in $D365FoInstance.

    .NOTES
        - Requires the dbatools PowerShell module for the Set-DbaMaxMemory cmdlet.
        - Requires WMI access to the target computer ($D365FoInstance).
        - The variable $D365FoInstance must be defined before calling this function.
        - Memory values are converted from bytes to MB internally.

    .OUTPUTS
        None. The function configures SQL Server settings but does not return output.
#>
function Set-DBMemory {
    param(
        [Parameter(Mandatory = $true)][Double]$factorPercent
    )

    #Set up SQL memory for use
    $totalServerMemory  = Get-WMIObject -Computername $D365FoInstance -class win32_ComputerSystem | Select-Object -Expand TotalPhysicalMemory
    $memoryForSqlServer = ($totalServerMemory * $factorPercent) / 1024 / 1024

    Set-DbaMaxMemory -SqlInstance $D365FoInstance -Max $memoryForSqlServer -WarningAction SilentlyContinue
}

<#
    .SYNOPSIS
        Installs SqlPackage.exe to a specified directory if it is not already present.

    .DESCRIPTION
        This function checks for the existence of SqlPackage.exe in the specified installation path. If it is not found, the function creates the directory (if necessary) and installs SqlPackage using the .NET tool installer.

    .PARAMETER InstallPath
        The directory where SqlPackage.exe should be installed. Default is "C:\Temp\d365fo.tools\SqlPackage".

    .EXAMPLE
        Install-SqlPackage -InstallPath "C:\CustomPath\SqlPackage"
        Installs SqlPackage.exe to the specified custom path.

    .NOTES
        - Requires internet access to download the SqlPackage tool.
        - The installation path must be writable by the user running the script.

    .OUTPUTS
        The full path to the installed SqlPackage.exe.
#>
function Install-SqlPackage {
    param(
        [string]$InstallPath = "C:\Temp\d365fo.tools\SqlPackage"
    )

    $sqlPackageExe = Join-Path $InstallPath "SqlPackage.exe"

    # Check if SqlPackage already exists
    if (Test-Path $sqlPackageExe) {
        Write-Host "SqlPackage.exe already exists at: $sqlPackageExe" -ForegroundColor Green
        return $sqlPackageExe
    }

    # Create install directory if it doesn't exist
    if (!(Test-Path $InstallPath)) {
        New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
    }

    try {
        # Extract the package
        Write-Host "Downloading and install package..." -ForegroundColor Cyan
        dotnet tool install Microsoft.SqlPackage --tool-path $InstallPath

        return $sqlPackageExe
    }
    catch {
        Write-Host "Error installing SqlPackage: $_" -ForegroundColor Red
        throw "Failed to install SqlPackage"
    }
}

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
    
    $Module2Service = $('dbatools', 'd365fo.tools')
    
    $Module2Service | ForEach-Object {
        if (Get-Module -ListAvailable -Name $_) {
            Write-Host "Updating " + $_
            Update-Module -Name $_ -Force
        } 
        else {
            Write-Host "Installing " + $_
            Install-Module -Name $_ -SkipPublisherCheck -Scope AllUsers
            Import-Module $_
        }
    }
}
#EndRegion Functions

#region first checks
if (!(test-path $BCPFilePath)) {
    New-Item -ItemType Directory -Force -Path $BCPFilePath
}

Write-Host ""
Write-Host ":: Installing required PowerShell modules" -ForegroundColor Green
Install-ModuleList
Write-Host ""
#endregion first checks

#region Export and Fix Model File
Write-Host ":: Export Model File from bacpac" -ForegroundColor Green
Export-D365BacpacModelFile -Path $BCPFile -OutputPath $BCPModelName -Force
Write-Host "File exported: $BCPModelName"
Write-Host ""

Write-Host ":: Fixing Model File" -ForegroundColor Green
Repair-D365BacpacModelFile -Path $BCPModelName -OutputPath $BCPModelName_Updated -PathRepairQualifier '' -PathRepairSimple $RepairScript -Force
Write-Host "File fixed: $BCPModelName_Updated"
Write-Host ""
#endregion Export and Fix Model File

#region Install SqlPackage
Write-Host ":: Checking SqlPackage installation" -ForegroundColor Green
$sqlPackageExe = Install-SqlPackage -InstallPath "C:\Temp\d365fo.tools\SqlPackage"
Write-Host ""
#endregion Install SqlPackage

#Region StartStopServices
Write-Host ":: Stop D365Fo services before import bacpac" -ForegroundColor Green
pwsh.exe -NoProfile -File $FileStartStop -ServiceStatus "Stop"
Write-Host ""
#endregion StartStopServices

#Todo: Create a licening to check if the new DB was created successfully, if created then apply the configurations to the new DB.

#region Import Bacpac
try {
    #Improve performance during import
    Write-Host ":: Increase SQL memory to 80%" -ForegroundColor Green
    Set-DBMemory -factorPercent 0.8
    Write-Host ""

    #import bacpac
    Write-Host ":: Import bacpac file $BCPFileName" -ForegroundColor Green
    & $sqlPackageExe /a:import /sf:$BCPFile /tsn:localhost /tdn:$NewDBName /mp:$NumLogicalProcessors /mfp:$BCPModelName_Updated /q:false /p:RebuildIndexesOfflineForDataPhase=True /p:DisableIndexesForDataPhase=True /p:CommandTimeout=1200 /TargetTrustServerCertificate:true /d:False /df:$LogRestore
    Write-Host ""

    #Decrease performance settings after import
    Write-Host ":: Decrease SQL memory to 60%" -ForegroundColor Green
    Set-DBMemory -factorPercent 0.6
    Write-Host ""
}
catch {
    Write-Host ":: Error during import bacpac"
    Write-Host ":: Decrease SQL memory to 60%" -ForegroundColor Green
    Set-DBMemory -factorPercent 0.6
}
#endregion Import Bacpac