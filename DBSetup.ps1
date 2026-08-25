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

Import-Module "$PSScriptRoot\Write-Log.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Invoke-SetupStep.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Invoke-WithRetry.psm1" -DisableNameChecking
Import-Module "$PSScriptRoot\Set-ScheduledTask.psm1" -DisableNameChecking

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

Write-Host "Step 13"
#region Update SSMS
if ($SetStepNumber -eq 13) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Update SSMS" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host "Update SSMS"

        if ((Test-Path $SSMSPath)) {
            Write-Host "Downloading SQL Server SSMS..."

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
            Write-Host "Download complete."

            Write-Host "Starting SSMS installer..."

            $Parms  = " /Install /Quiet /Norestart /Logs log.txt"
            $Prms   = $Parms.Split(" ")
            & "$Filepath" $Prms | Out-Null

            Remove-Item $Filepath -Recurse -Force -Confirm:$false
            Write-Host "SSMS installation complete"
        }
    }
}
#endRegion

Write-Host "Step 14"
#region Update SQL Server Version (CU-KB)
if ($SetStepNumber -eq 14) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Update SQL Server Version (CU-KB)" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host "Update SQL Server Version (CU-KB)"

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
            Write-Host "No updates available. Current version: $($BuildTargets.BuildTarget)"
        }
    }
}
#endRegion

Write-Host "Step 15"
#region Install Features, Set up DB server
if ($SetStepNumber -eq 15) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Install Features, Set up DB server" -LogPath $LogPath -FileName $FileName -Action {
        if (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {

            Write-Host "Install Features, Set up DB server"

            Set-DbatoolsConfig -FullName 'sql.connection.trustcert' -Value $true -Register
            Set-DbaPrivilege -Type LPIM, IFI

            Write-Host "Install Ola Hallengren's SQL Maintenance Solution"
            Install-DbaMaintenanceSolution -SqlInstance . -Database master

            Write-Host "Install First Aid Kit Responder PowerShell Module"
            Install-DbaFirstResponderKit -SqlInstance . -Database master

            Write-Host "Enable trace flags for SQL Server"
            Enable-DbaTraceFlag -SqlInstance . -TraceFlag 174, 834, 1204, 1222, 1224, 2505, 7412

            Write-Host "Setting recovery model"
            Set-DbaDbRecoveryModel -SqlInstance . -RecoveryModel Simple -Database AxDB -Confirm:$false

            Write-Host "Setting max memory"
            Set-DBMemory -factorPercent 0.6

            Write-Host "Restarting service"
            Restart-DbaService -Type Engine -Force
        }
    }
}
#endRegion

Write-Host "Step 16"
#region Purge unnecessary data, Set up Ax Batch Jobs
if ($SetStepNumber -eq 16) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Purge unnecessary data, Set up Ax Batch Jobs" -LogPath $LogPath -FileName $FileName -Action {
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
                            ,"TRUNCATE TABLE SUNTAFRELEASEFAILURES"
                            ,"TRUNCATE TABLE SUNTAFRELEASELOGLINEDETAILS"
                            ,"TRUNCATE TABLE SUNTAFRELEASELOGTABLE"
                            ,"TRUNCATE TABLE SUNTAFRELEASELOGTRANS"
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
            }
        }
    }
}
#endRegion

Write-Host "Step 17"
#region Reclaiming freed database space and log files
if ($SetStepNumber -eq 17) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Reclaiming freed database space and log files" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host "Reclaiming freed database space"
        Invoke-DbaDbShrink -SqlInstance $D365FoInstance -Database $D365FoDatabase, "DYNAMICSXREFDB" -FileType Data, Log -Confirm:$false -Verbose

        Write-Host "Reclaiming database log space"
        Invoke-DbaDbShrink -SqlInstance $D365FoInstance -Database $D365FoDatabase, "DYNAMICSXREFDB" -FileType Log -ShrinkMethod TruncateOnly -Confirm:$false -Verbose
    }
}
#endRegion

Write-Host "Step 18"
#region Running Ola Hallengren's IndexOptimize tool
if ($SetStepNumber -eq 18) {
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Running Ola Hallengren's IndexOptimize tool" -LogPath $LogPath -FileName $FileName -Action {
        Write-Host "Running Ola Hallengren's IndexOptimize tool"
        $SQLQuery = "EXECUTE master.dbo.IndexOptimize
                    @Databases = 'ALL_DATABASES',
                    @FragmentationLow = NULL,
                    @FragmentationMedium = 'INDEX_REBUILD_OFFLINE',
                    @FragmentationHigh = 'INDEX_REBUILD_OFFLINE',
                    @FragmentationLevel1 = 5,
                    @FragmentationLevel2 = 25,
                    @LogToTable = 'N',
                    @MaxDOP = 0,
                    @Online = 'N',
                    @UpdateStatistics = 'ALL',
                    @OnlyModifiedStatistics = 'Y'"

        Invoke-DbaQuery -Query $SQLQuery -SqlInstance $D365FoInstance -database $D365FoDatabase -QueryTimeout 0 -ErrorAction Stop -Verbose
    }
}
#endRegion

Wait-ForKeyPress
