
# ============================================
# D365FO Database Synchronization Script
# ============================================

# Parameters (adjust for your VM)
$currentDir     = $PSScriptRoot
$setupPathDir   = "C:\AOSService\PackagesLocalDirectory\bin\"
$BinDirTools    = 'C:\AOSService\PackagesLocalDirectory\'
$MetadataDir    = 'C:\AOSService\PackagesLocalDirectory\'
$SyncMode       = "Full"
$DatabaseServer = "."
$DatabaseName   = "AxDB"
$SqlUser        = "axdbadmin"
$SqlPassword    = "AOSWebSite@123"
$LogPath        = "C:\Temp\dbsync.log"

$dbConnnectionString = "Data Source=$DatabaseServer;Initial Catalog=$DatabaseName;Integrated Security=True;Enlist=True;Application Name=SyncEngine"
                       


# Ensure log folder exists
if (-not (Test-Path (Split-Path $LogPath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
}

# Import d365fo.tools module (if installed)
Import-Module d365fo.tools #-ErrorAction Stop

Write-Host "Starting D365FO DB Sync..." -ForegroundColor Cyan

try {
    $setupExe = Join-Path $setupPathDir "SyncEngine.exe"
    #Add-type -Path $setupExe
    # Execute the SyncEngine.exe with arguments. Use the call operator (&) to run the executable
    & $setupExe "-syncmode" "fullall" "-metadatabinaries=$MetadataDir" "-connect=$dbConnnectionString" "-fallbacktonative=False" "-raiseDataEntityViewSyncNotification" > $LogPath

    Write-Host "✅ Database synchronization completed successfully." -ForegroundColor Green
    Write-Host "Log file: $LogPath"
}
catch {
    Write-Host "❌ DB Sync failed!" -ForegroundColor Red
    Write-Host $_.Exception.Message
    ##exit 1
}

Write-Host "Script finished."
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
``
