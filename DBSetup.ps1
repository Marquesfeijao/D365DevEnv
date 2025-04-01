[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $false)]
    [int]$SetStepNumber = 0
)

#region Set up script
$CurrentPath    = (Get-Location).Path
$FileName       = "taskLog.txt"
$LogPath        = $CurrentPath + "\Logs\"
$D365FoDatabase = "AxDB"
$D365FoInstance = "."

if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Force -Path $LogPath
}

if (!(Test-Path "$LogPath\$FileName")) {
    New-Item -Path "$LogPath\$FileName" -ItemType File -Force
}

if ($SetStepNumber -eq 0) {
    $SetStepNumber = 1
}
elseif ($SetStepNumber -notin 1..8) {
    Write-Host "Please enter a valid step number between 1 and 8"
    Exit
}
#endRegion

#region Functions
function Write-Log {
    param (
        [Parameter(Mandatory = $true)][string]$StepProcess,
        [Parameter(Mandatory = $true)][int]$StepNum,
        [Parameter(Mandatory = $true)][string]$PathLog,
        [Parameter(Mandatory = $true)][string]$FileName
    )

    $StepExecution = ""

    try {
        switch ($StepProcess) {
            "StepStart" { $StepExecution = "Step $StepNum start" }
            "StepComplete" { $StepExecution = "Step $StepNum complete" }
            "StepError" { $StepExecution = "Step $StepNum not complete" }
            default { $StepExecution = "Unknown step process" }
        }

        Write-Output $StepExecution | Out-File "$PathLog\$FileName" -Append -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to write log: $($_.Exception.Message)"
    }
}

function Invoke-Sql {
    param(
        [Parameter(Mandatory = $true)][string]$server,
        [Parameter(Mandatory = $true)][string]$database,
        [Parameter(Mandatory = $true)][string]$sqlCommand
    )

    Process {
        $SQLConnection = New-Object System.Data.SqlClient.SqlConnection
        $SQLConnection.ConnectionString = "Data Source=$server;Initial Catalog=$database;Integrated Security=true"

        $Command = New-Object System.Data.SqlClient.SqlCommand
        $Command.Connection = $SQLConnection
        $Command.CommandTimeout = 0
        $Command.CommandText = $sqlCommand

        try {
            $SQLConnection.Open()
            $Command.ExecuteNonQuery()
        }
        catch [Exception] {
            Write-Warning $_.Exception.Message
        }
        finally {
            $SQLConnection.Dispose()
            $Command.Dispose()
        }
    }
}

function Set-DBMemory {
    param(
        [Parameter(Mandatory = $true)][real]$factorPercent
    )

    #Set up SQL memory for use
    $totalServerMemory = Get-WMIObject -Computername . -class win32_ComputerSystem | Select-Object -Expand TotalPhysicalMemory
    $memoryForSqlServer = ($totalServerMemory * $factorPercent) / 1024 / 1024

    Set-DbaMaxMemory -SqlInstance . -Max $memoryForSqlServer
}
#endregion

Write-Host "Step 1"
#region Update SSMS
if ($SetStepNumber -eq 1) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "Update SSMS"

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        
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

Write-Host "Step 2"
#region Update DB Version (CU-KB)
if ($SetStepNumber -eq 2) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

        Write-Host "Update DB Version (CU-KB)"

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        dotnet nuget add source "https://api.nuget.org/v3/index.json" --name "nuget.org"
        dotnet tool update -g dotnet-vs
        
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User") 
        
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host $_.Exception.Message

        $SetStepNumber = 2
        Exit
    }
}
#endRegion

Write-Host "Step 3"
#region Install Features, Set up DB server 
if ($SetStepNumber -eq 3) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

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
            
            Write-Host "Restarting service"
            Restart-DbaService -Type Engine -Force        
        }
        
        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host "Error message: " + $_.Exception.Message

        $SetStepNumber = 3
        Exit
    }
}
#endRegion

Write-Host "Step 4"
#region Purge unnecessary data, Set up Ax Batch Jobs
if ($SetStepNumber -eq 1) {
    try {
        Write-Log -StepProcess "StepStart" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName

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

        Write-Log -StepProcess "StepComplete" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        
        $SetStepNumber++
    }
    catch {
        Write-Log -StepProcess "StepError" -StepNum $SetStepNumber -PathLog $LogPath -FileName $FileName
        Write-Host "Set up Nuget Step $SetStepNumber failed"
        Write-Host "Error message: " + $_.Exception.Message

        $SetStepNumber = 4
        Exit
    }
}
#endRegion
