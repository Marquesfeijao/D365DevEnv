
# ============================================
# D365FO Database Synchronization Script
# ============================================

# Parameters (adjust for your VM)
$currentDir     = $PSScriptRoot

$setupPathDir   = "C:\AOSService\PackagesLocalDirectory\bin\"
$BinDirTools    = 'C:\AOSService\PackagesLocalDirectory\bin\'
$MetadataDir    = 'C:\AOSService\PackagesLocalDirectory\'
$SyncMode       = "fullall" # Options: fullall | initialschema | fullsecurity | fullids | fulltablesandviews | partiallist | drop | drop,partiallist | partialsecurity | partiallist,partialsecurity | analysisonly | precheck
$DatabaseServer = "."
$DatabaseName   = "AxDB"
$SqlUser        = "axdbadmin"
$SqlPassword    = "AOSWebSite@123"

$Verbosity      = "Diagnostic" # Options: Normal | Diagnostic

$LogFileName    = "DBSync_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$LogFileNameErr = "DBSync_$(Get-Date -Format 'yyyyMMdd_HHmmss').err"

$LogPath        = Join-Path $currentDir "\Logs\"$LogFileName
$LogPathErr     = Join-Path $currentDir "\Logs\"$LogFileNameErr

$dbConnnectionString = "Data Source=$DatabaseServer;Initial Catalog=$DatabaseName;Integrated Security=True;Enlist=True;Application Name=SyncEngine"

# Ensure log folder exists
if (-not (Test-Path (Split-Path $LogPath))) {
    New-Item -Path "$LogPath\$LogFileName" -ItemType File -Force | Out-Null
    New-Item -Path "$LogPath\$LogFileNameErr" -ItemType File -Force | Out-Null
}

try {
    Write-Host "Starting D365FO DB Sync..." -ForegroundColor Cyan

    $setupExe = Join-Path $setupPathDir "SyncEngine.exe"
    # Add-Type -Path $setupExe
    # Execute the SyncEngine.exe with arguments. Use the call operator (&) to run the executable
    & $setupExe "-syncmode=$SyncMode" "-metadatabinaries=$MetadataDir" "-connect=$dbConnnectionString" "-verbosity=$Verbosity" "-fallbacktonative=False" > $LogPathErr | Tee-Object -FilePath $LogPath

    Write-Host "✅ Database synchronization completed successfully." -ForegroundColor Green
    Write-Host "Log file: $LogPath"
}
catch {
    Write-Host "❌ DB Sync failed!" -ForegroundColor Red
    Write-Host "Log file: $LogPathErr"
    Write-Host $_.Exception.Message
    ##exit 1
}

Write-Host "Script finished."
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
``
