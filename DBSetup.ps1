[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $false)]
    [int]$SetStepNumber = 0
)

#region Set up script
$CurrentPath    = $PSScriptRoot
$FileName       = "taskLog.txt"
$LogPath        = Join-Path $CurrentPath "Logs"
$AddinPath      = Join-Path $CurrentPath "Addin"
$SSMSPath       = Join-Path $CurrentPath "SSMS_KB"
$DownloadPath   = Join-Path $CurrentPath "SQLKB"
$DeployPackages = Join-Path $CurrentPath "DeployablePackages"
$D365FoDatabase = "AxDB"
$D365FoInstance = "."

Import-Module "$PSScriptRoot\Modules\Write-Log.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Modules\Invoke-SetupStep.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Modules\Invoke-WithRetry.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Modules\Set-ScheduledTask.psm1" -DisableNameChecking

try {
    Initialize-WorkDirectory -Path $LogPath

    if (!(Test-Path "$LogPath\$FileName")) {
        New-Item -Path "$LogPath\$FileName" -ItemType File -Force | Out-Null
    }

    Initialize-WorkDirectory -Path $AddinPath -ClearIfExists
    Initialize-WorkDirectory -Path $SSMSPath -ClearIfExists
    Initialize-WorkDirectory -Path $DownloadPath -ClearIfExists
    Initialize-WorkDirectory -Path $DeployPackages
}
catch {
    Write-Host "Failed to initialize working directories: $($_.Exception.Message)"
    Exit 3
}

Set-TlsSecurityProtocol

$SetStepNumber = Confirm-StepNumber -RequestedStep $SetStepNumber -DefaultStep 13 -MinStep 13 -MaxStep 18
#endRegion

#region Functions
<#
.SYNOPSIS
    Executes a non-query SQL command against a SQL Server database.

.DESCRIPTION
    Opens a connection to the specified SQL Server instance and database using integrated
    security, runs the supplied T-SQL command with no command timeout, and disposes the
    connection and command objects when finished. Errors are caught and written as a warning
    rather than being thrown.

.PARAMETER server
    The SQL Server instance to connect to.

.PARAMETER database
    The name of the database to run the command against.

.PARAMETER sqlCommand
    The T-SQL command text to execute.

.EXAMPLE
    Invoke-Sql -server "." -database "AxDB" -sqlCommand "TRUNCATE TABLE dbo.SomeTable"

.OUTPUTS
    System.Int32 — the number of rows affected, as returned by ExecuteNonQuery.
#>
function Invoke-Sql {
    param(
        [Parameter(Mandatory = $true)][string]$server,
        [Parameter(Mandatory = $true)][string]$database,
        [Parameter(Mandatory = $true)][string]$sqlCommand
    )

    Process {
        $SQLConnection                  = New-Object System.Data.SqlClient.SqlConnection
        $SQLConnection.ConnectionString = "Data Source=$server;Initial Catalog=$database;Integrated Security=true"

        $Command                        = New-Object System.Data.SqlClient.SqlCommand
        $Command.Connection             = $SQLConnection
        $Command.CommandTimeout         = 0
        $Command.CommandText            = $sqlCommand

        try {
            $SQLConnection.Open()
            $Command.ExecuteNonQuery()
        }
        catch [Exception] {
            Write-Warning "Error message: " + $_.Exception.Message
        }
        finally {
            $SQLConnection.Dispose()
            $Command.Dispose()
        }
    }
}

<#
.SYNOPSIS
    Configures the maximum memory allocation for SQL Server based on a percentage of total system memory.

.DESCRIPTION
    Retrieves the total physical memory of the computer hosting the $D365FoInstance SQL Server
    instance, calculates a target amount from the given percentage, and applies it as the
    instance's max server memory setting via Set-DbaMaxMemory.

.PARAMETER factorPercent
    The percentage of total physical memory to allocate to SQL Server, expressed as a decimal
    (e.g. 0.6 for 60%).

.EXAMPLE
    Set-DBMemory -factorPercent 0.6
    Allocates 60% of the total physical memory to the SQL Server instance stored in $D365FoInstance.

.NOTES
    Requires the dbatools PowerShell module for Set-DbaMaxMemory, and the $D365FoInstance
    variable to be defined in the calling scope.
#>
function Set-DBMemory {
    param(
        [Parameter(Mandatory = $true)][Double]$factorPercent
    )

    #Set up SQL memory for use
    $totalServerMemory  = Get-WMIObject -Computername $D365FoInstance -class win32_ComputerSystem | Select-Object -Expand TotalPhysicalMemory
    $memoryForSqlServer = ($totalServerMemory * $factorPercent) / 1024 / 1024

    Set-DbaMaxMemory -SqlInstance $D365FoInstance -Max $memoryForSqlServer
}
#endregion

Write-Host ""
Write-Host ":: Executing step: 13" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Update SSMS
if ($SetStepNumber -eq 13) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Update SSMS" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host ""
        Write-Host "Update SSMS" -ForegroundColor Cyan

        if ((Test-Path $SSMSPath)) {
            Write-Host ""
            Write-Host "Downloading SQL Server SSMS..." -ForegroundColor Cyan

            $Filepath   = Join-Path $SSMSPath "SSMS-Setup-ENU.exe"
            $URL        = "https://aka.ms/ssmsfullsetup"

            Invoke-WithRetry -OperationName "SSMS download" -ScriptBlock {
                $WebClient = New-Object System.Net.WebClient
                try {
                    $WebClient.DownloadFile($URL, $Filepath)
                }
                finally {
                    $WebClient.Dispose()
                }
            }

            Write-Host ""
            Write-Host "Download complete." -ForegroundColor Cyan

            Write-Host ""
            Write-Host "Starting SSMS installer..." -ForegroundColor Cyan

            $Parms  = " /Install /Quiet /Norestart /Logs log.txt"
            $Prms   = $Parms.Split(" ")
            & "$Filepath" $Prms | Out-Null

            Remove-Item $Filepath -Recurse -Force -Confirm:$false
            Write-Host "SSMS installation complete" -ForegroundColor Cyan
        }
    }

    $SetStepNumber = 14
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 13 is completed" -ForegroundColor Green

Write-Host ""
Write-Host ":: Executing step: 14" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Update SQL Server Version (CU-KB)
if ($SetStepNumber -eq 14) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Update SQL Server Version (CU-KB)" -LogPath $LogPath -FileName $FileName -Action {
        try {
            Write-Host ""
            Write-Host "Update SQL Server Version (CU-KB)" -ForegroundColor Cyan

            Set-DbatoolsConfig -FullName 'sql.connection.trustcert' -Value $true -Register

            $BuildTargets = Test-DbaBuild -SqlInstance $D365FoInstance -MaxBehind "0CU" -Update | Where-Object {
                !$PSItem.Compliant
            } | Select-Object -ExpandProperty BuildTarget -Unique

            if ($BuildTargets)
            {
                Get-DbaBuildReference -Build $BuildTargets.BuildTarget | ForEach-Object {
                    Invoke-WithRetry -OperationName "SQL KB download ($($PSItem.KBLevel))" -ScriptBlock {
                        Save-DbaKBUpdate -Path $DownloadPath -Name $PSItem.KBLevel
                    }
                }

                Update-DbaInstance -ComputerName . -Path $DownloadPath -Confirm:$false
                Remove-Item $DownloadPath -Recurse -Force -Confirm:$false
            }
            else {
                $BuildTargets = Test-DbaBuild -SqlInstance $D365FoInstance -MaxBehind "0CU"
                Write-Host ""
                Write-Host "No updates available. Current version: $($BuildTargets.BuildTarget)" -ForegroundColor Cyan
            }
        }
        catch {
            Write-Host "❌ SQL Server update failed!" -ForegroundColor Red
            Write-Host "Error message: $($_.Exception.Message)"
        }
    }

    $SetStepNumber = 15
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 14 is completed" -ForegroundColor Green

Write-Host ""
Write-Host ":: Executing step: 15" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Install Features, Set up DB server
if ($SetStepNumber -eq 15) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Install Features, Set up DB server" -LogPath $LogPath -FileName $FileName -Action {        
        try {
            if (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
                Write-Host ""
                Write-Host "Install Features, Set up DB server" -ForegroundColor Cyan

                Set-DbatoolsConfig -FullName 'sql.connection.trustcert' -Value $true -Register
                Set-DbaPrivilege -Type LPIM, IFI

                Write-Host ""
                Write-Host "Install Ola Hallengren's SQL Maintenance Solution" -ForegroundColor Cyan
                Install-DbaMaintenanceSolution -SqlInstance . -Database master

                Write-Host ""
                Write-Host "Install First Aid Kit Responder PowerShell Module" -ForegroundColor Cyan
                Install-DbaFirstResponderKit -SqlInstance . -Database master

                Write-Host ""
                Write-Host "Enable trace flags for SQL Server" -ForegroundColor Cyan
                Enable-DbaTraceFlag -SqlInstance . -TraceFlag 174, 834, 1204, 1222, 1224, 2505, 7412

                Write-Host ""
                Write-Host "Setting recovery model" -ForegroundColor Cyan
                Set-DbaDbRecoveryModel -SqlInstance . -RecoveryModel Simple -Database AxDB -Confirm:$false

                Write-Host ""
                Write-Host "Setting max memory" -ForegroundColor Cyan
                Set-DBMemory -factorPercent 0.6

                Write-Host ""
                Write-Host "Restarting service" -ForegroundColor Cyan
                Restart-DbaService -Type Engine -Force
            }
        }
        catch {
            Write-Host "❌ DB server setup failed!" -ForegroundColor Red
            Write-Host "Error message: $($_.Exception.Message)"
        }
    }

    $SetStepNumber = 16
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 15 is completed" -ForegroundColor Green

Write-Host ""
Write-Host ":: Executing step: 16" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Purge unnecessary data, Set up Ax Batch Jobs
if ($SetStepNumber -eq 16) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Purge unnecessary data, Set up Ax Batch Jobs" -LogPath $LogPath -FileName $FileName -Action {
        try {
            if (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
                Write-Host "Purge unnecessary data, Set up Ax Batch Jobs"

                Write-Host "Purging data: Truncate tables"
                $PurgeTables = @("TRUNCATE TABLE BATCHJOBHISTORY"
                                ,"TRUNCATE TABLE BATCHCONSTRAINTSHISTORY"
                                ,"TRUNCATE TABLE BATCHHISTORY"
                                ,"TRUNCATE TABLE DMFDEFINITIONGROUPEXECUTION"
                                ,"TRUNCATE TABLE DMFDEFINITIONGROUPEXECUTIONHISTORY"
                                ,"TRUNCATE TABLE DMFEXECUTION"
                                ,"TRUNCATE TABLE DMFSTAGINGEXECUTIONERRORS"
                                ,"TRUNCATE TABLE DMFSTAGINGLOG"
                                ,"TRUNCATE TABLE DMFSTAGINGLOGDETAILS"
                                ,"TRUNCATE TABLE DMFSTAGINGVALIDATIONLOG"
                                ,"TRUNCATE TABLE EVENTCUD"
                                ,"TRUNCATE TABLE EVENTCUDLINES"
                                ,"TRUNCATE TABLE FORMRUNCONFIGURATION"
                                ,"TRUNCATE TABLE INVENTSUMLOGTTS"
                                ,"TRUNCATE TABLE MP.PEGGINGIDMAPPING"
                                ,"TRUNCATE TABLE REQPO"
                                ,"TRUNCATE TABLE REQTRANS"
                                ,"TRUNCATE TABLE REQTRANSCOV"
                                ,"TRUNCATE TABLE RETAILLOG"
                                ,"TRUNCATE TABLE SALESPARMLINE"
                                ,"TRUNCATE TABLE SALESPARMSUBLINE"
                                ,"TRUNCATE TABLE SALESPARMSUBTABLE"
                                ,"TRUNCATE TABLE SALESPARMTABLE"
                                ,"TRUNCATE TABLE SALESPARMUPDATE"
                                ,"TRUNCATE TABLE SYSDATABASELOG"
                                ,"TRUNCATE TABLE SYSLASTVALUE"
                                ,"TRUNCATE TABLE SYSUSERLOG"
                                )

                $PurgeTables | ForEach-Object {
                    Write-Host "Purging: $_"

                    try {
                        Invoke-DbaQuery -Query $_ -SqlInstance $D365FoInstance -database $D365FoDatabase -QueryTimeout 0 -ErrorAction Stop -Verbose
                    } catch {
                        Write-Host "Error in query: $_"
                        Write-Host "Error message: " + $_.Exception.Message
                    }
                }

                Write-Host "Purging data: Deleting by filter"
                $SQLQuery = @("ALTER DATABASE [AXDB] SET AUTO_CLOSE OFF"
                            ,"ALTER DATABASE [AXDB] SET AUTO_UPDATE_STATISTICS_ASYNC OFF"
                            ,"DELETE BATCHSERVERGROUP WHERE SERVERID <> 'BATCH:'+@@SERVERNAME"
                            ,"INSERT INTO BATCHSERVERGROUP(GROUPID, SERVERID, RECID, RECVERSION, CREATEDDATETIME, CREATEDBY)
                            SELECT GROUP_, 'BATCH:'+@@SERVERNAME, 5900000000 + CAST(CRYPT_GEN_RANDOM(4) AS BIGINT), 1, GETUTCDATE(), '-ADMIN-' FROM BATCHGROUP
                            WHERE NOT EXISTS (SELECT RECID FROM BATCHSERVERGROUP WHERE BATCHSERVERGROUP.GROUPID = BATCHGROUP.GROUP_)"
                            ,"DELETE BATCHJOB WHERE STATUS IN (3, 4, 8)"
                            ,"DELETE BATCH WHERE NOT EXISTS (SELECT RECID FROM BATCHJOB WHERE BATCH.BATCHJOBID = BATCHJOB.RECID)"
                            ,"EXEC SP_MSFOREACHTABLE @COMMAND1 ='TRUNCATE TABLE ?'
                            ,@WHEREAND = ' AND OBJECT_ID IN (SELECT OBJECT_ID FROM SYS.OBJECTS
                            WHERE NAME LIKE ''%STAGING'')'"
                            ,"EXEC SP_MSFOREACHTABLE
                            @COMMAND1 ='TRUNCATE TABLE ?'
                            ,@WHEREAND = ' AND OBJECT_ID IN (SELECT OBJECT_ID FROM SYS.OBJECTS
                            WHERE NAME LIKE ''%TMP'')'"
                            ,"EXEC SP_MSFOREACHTABLE
                            @COMMAND1 ='DROP TABLE ?'
                            ,@WHEREAND = ' AND OBJECT_ID IN (SELECT OBJECT_ID FROM SYS.OBJECTS AS O WITH (NOLOCK), SYS.SCHEMAS AS S WITH (NOLOCK) WHERE S.NAME = ''DBO'' AND S.SCHEMA_ID = O.SCHEMA_ID AND O.TYPE = ''U'' AND O.NAME LIKE ''T[0-9]%'')' "
                            ,"EXEC SP_MSFOREACHTABLE
                            @COMMAND1 ='DROP TABLE ?'
                            ,@WHEREAND = ' AND OBJECT_ID IN (SELECT OBJECT_ID FROM SYS.OBJECTS AS O WITH (NOLOCK), SYS.SCHEMAS AS S WITH (NOLOCK) WHERE S.NAME = ''DBO'' AND S.SCHEMA_ID = O.SCHEMA_ID AND O.TYPE = ''U'' AND O.NAME LIKE ''DMF_OLEDB_ERROR_%'')' "
                            ,"EXEC SP_MSFOREACHTABLE
                            @COMMAND1 ='DROP TABLE ?'
                            ,@WHEREAND = ' AND OBJECT_ID IN (SELECT OBJECT_ID FROM SYS.OBJECTS AS O WITH (NOLOCK), SYS.SCHEMAS AS S WITH (NOLOCK) WHERE S.NAME = ''DBO'' AND S.SCHEMA_ID = O.SCHEMA_ID AND O.TYPE = ''U'' AND O.NAME LIKE ''DMF_FLAT_ERROR_%'')' "
                            ,"EXEC SP_MSFOREACHTABLE
                            @COMMAND1 ='DROP TABLE ?'
                            ,@WHEREAND = ' AND OBJECT_ID IN (SELECT OBJECT_ID FROM SYS.OBJECTS AS O WITH (NOLOCK), SYS.SCHEMAS AS S WITH (NOLOCK) WHERE S.NAME = ''DBO'' AND S.SCHEMA_ID = O.SCHEMA_ID AND O.TYPE = ''U'' AND O.NAME LIKE ''DMF[_][0-9A-ZA-Z]%'')' "
                            )

                $SQLQuery | ForEach-Object {
                    Write-Host "Change data: $_"

                    try {
                        Invoke-DbaQuery -Query $_ -SqlInstance $D365FoInstance -database $D365FoDatabase -QueryTimeout 0 -ErrorAction Stop -Verbose
                    } catch {
                        Write-Host "Error message: " + $_.Exception.Message
                    }
                } | Out-Null
            }            
        }
        catch {
            Write-Host "❌ Data purge or batch job setup failed!" -ForegroundColor Red
            Write-Host "Error message: $($_.Exception.Message)"
        }
    }

    $SetStepNumber = 17
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 16 is completed" -ForegroundColor Green

Write-Host ""
Write-Host ":: Executing step: 17" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Reclaiming freed database space and log files
if ($SetStepNumber -eq 17) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Reclaiming freed database space and log files" -LogPath $LogPath -FileName $FileName -Action {    
        try {
            Write-Host ""
            Write-Host "Reclaiming freed database space" -ForegroundColor Cyan
            Invoke-DbaDbShrink -SqlInstance $D365FoInstance -Database $D365FoDatabase, "DYNAMICSXREFDB" -FileType Data -Confirm:$false -Verbose

            Write-Host ""
            Write-Host "Reclaiming database log space" -ForegroundColor Cyan
            Invoke-DbaDbShrink -SqlInstance $D365FoInstance -Database $D365FoDatabase, "DYNAMICSXREFDB" -FileType Log -ShrinkMethod TruncateOnly -Confirm:$false -Verbose
        }
        catch {
            Write-Host "❌ Database shrink failed!" -ForegroundColor Red
            Write-Host "Error message: $($_.Exception.Message)"
        }
    }

    $SetStepNumber = 18
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 17 is completed" -ForegroundColor Green

Write-Host ""
Write-Host ":: Executing step: 18" -ForegroundColor Green
Write-Host "-------------------------------------------------" -ForegroundColor Green
#region Running Ola Hallengren's IndexOptimize tool
if ($SetStepNumber -eq 18) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Running Ola Hallengren's IndexOptimize tool" -LogPath $LogPath -FileName $FileName -Action {
        try {
            Write-Host ""
            Write-Host "Running Ola Hallengren's IndexOptimize tool" -ForegroundColor Cyan
            $SQLQuery = "EXECUTE master.dbo.IndexOptimize
                        @Databases = 'ALL_DATABASES',
                        @FragmentationLow = NULL,
                        @FragmentationMedium = 'INDEX_REBUILD_OFFLINE',
                        @FragmentationHigh = 'INDEX_REBUILD_OFFLINE',
                        @FragmentationLevel1 = 5,
                        @FragmentationLevel2 = 25,
                        @LogToTable = 'N',
                        @MaxDOP = 0,
                        @UpdateStatistics = 'ALL',
                        @OnlyModifiedStatistics = 'Y'"

            Invoke-Sql -server "." -database "master" -SQLCommand $SQLQuery
        }
        catch {
            Write-Host "❌ Index optimization failed!" -ForegroundColor Red
            Write-Host "Error message: $($_.Exception.Message)"
        }
    }

    $SetStepNumber = 19
}
#endRegion
Write-Host "-------------------------------------------------" -ForegroundColor Green
Write-Host ":: The step 18 is completed" -ForegroundColor Green

Write-Host ""
Write-Host "Setup completed. Press any key to exit." -ForegroundColor Green
Wait-ForKeyPress
