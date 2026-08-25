<#
.SYNOPSIS
    Writes a log entry to the specified log file.
.DESCRIPTION
    This function appends a log entry to the specified log file, indicating the status of a specific step in the setup process.
.PARAMETER StepProcess
    The process status of the step (e.g., "StepStart", "StepComplete", "StepError").
.PARAMETER StepNum
    The step number being logged.
.PARAMETER PathLog
    The path to the log directory.
.PARAMETER FileName
    The name of the log file.
#>
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

        Write-Output $StepExecution | Out-File (Join-Path $PathLog $FileName) -Append -Encoding utf8 -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to write log: $($_.Exception.Message)"
    }
}
