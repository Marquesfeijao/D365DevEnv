<#
.SYNOPSIS
    Shared step-number validation, work-directory setup, and step-execution scaffolding used by
    the step-driven provisioning scripts (WindowsSetup.ps1, InstallUpdateApps.ps1, DBSetup.ps1).
#>

Import-Module "$PSScriptRoot\Write-Log.psm1" -DisableNameChecking

<#
.SYNOPSIS
    Resolves the step number to run, defaulting or validating against the caller's valid range.
.DESCRIPTION
    If $RequestedStep is 0 (the parameter's unset default), returns $DefaultStep. Otherwise,
    if $RequestedStep falls outside $MinStep..$MaxStep, prints a usage message and exits the
    process with code 2. Otherwise returns $RequestedStep unchanged.
.PARAMETER RequestedStep
    The step number passed in by the caller (typically -SetStepNumber).
.PARAMETER DefaultStep
    The step number to use when $RequestedStep is 0.
.PARAMETER MinStep
    The lowest valid step number for this script.
.PARAMETER MaxStep
    The highest valid step number for this script.
.EXAMPLE
    $SetStepNumber = Confirm-StepNumber -RequestedStep $SetStepNumber -DefaultStep 1 -MinStep 1 -MaxStep 8
#>
function Confirm-StepNumber {
    param(
        [Parameter(Mandatory = $true)][int]$RequestedStep,
        [Parameter(Mandatory = $true)][int]$DefaultStep,
        [Parameter(Mandatory = $true)][int]$MinStep,
        [Parameter(Mandatory = $true)][int]$MaxStep
    )

    if ($RequestedStep -eq 0) {
        return $DefaultStep
    }

    if ($RequestedStep -notin $MinStep..$MaxStep) {
        Write-Host "Please enter a valid step number between $MinStep and $MaxStep"
        Exit 2
    }

    return $RequestedStep
}

<#
.SYNOPSIS
    Ensures a working directory exists, optionally clearing its contents if it already does.
.PARAMETER Path
    The directory path to ensure exists.
.PARAMETER ClearIfExists
    If set, and the directory already exists, removes its contents (but not the directory
    itself).
.EXAMPLE
    Initialize-WorkDirectory -Path $LogPath
.EXAMPLE
    Initialize-WorkDirectory -Path $AddinPath -ClearIfExists
#>
function Initialize-WorkDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$ClearIfExists
    )

    if (!(Test-Path $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
    elseif ($ClearIfExists) {
        Get-ChildItem $Path -Recurse | Remove-Item -Force -Confirm:$false
    }
}

<#
.SYNOPSIS
    Runs one numbered setup step with consistent start/complete/error logging and failure
    handling.
.DESCRIPTION
    Logs "StepStart", invokes $Action, and on success logs "StepComplete" and returns
    $StepNumber + 1 so the caller can advance $SetStepNumber. On failure, logs "StepError"
    (including the actual exception message, via Write-Log) and exits the process with code 1
    so the step is retried (the caller's $SetStepNumber is left unchanged since the failing
    Exit happens before any return). A step whose action itself needs to end the process early
    (e.g. after registering a reboot-resume scheduled task) may call Exit directly from within
    $Action.
.PARAMETER StepNumber
    The step number currently executing.
.PARAMETER StepName
    A short human-readable name for the step, used in log/failure messages.
.PARAMETER LogPath
    The path to the log directory (passed through to Write-Log).
.PARAMETER FileName
    The log file name (passed through to Write-Log).
.PARAMETER Action
    A scriptblock containing the step's actual work. Any terminating error thrown inside is
    treated as a step failure.
.EXAMPLE
    $SetStepNumber = Invoke-SetupStep -StepNumber $SetStepNumber -StepName "Set up Nuget" -LogPath $LogPath -FileName $FileName -Action {
        # step body
    }
#>
function Invoke-SetupStep {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)][int]$StepNumber,
        [Parameter(Mandatory = $true)][string]$StepName,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    Write-Log -Level StepStart -StepNum $StepNumber -Message $StepName -LogPath $LogPath -FileName $FileName

    try {
        & $Action

        Write-Log -Level StepComplete -StepNum $StepNumber -Message $StepName -LogPath $LogPath -FileName $FileName

        return $StepNumber + 1
    }
    catch {
        Write-Log -Level StepError -StepNum $StepNumber -Message "($StepName) failed: $($_.Exception.Message)" -LogPath $LogPath -FileName $FileName

        Exit 1
    }
}
