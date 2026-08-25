<#
.SYNOPSIS
   Sets a scheduled task to run a specific step in the Windows setup script.
.DESCRIPTION
   This function creates a scheduled task that runs a specific step in the Windows setup script
   with the provided task name, step number, and description.
.PARAMETER TaskName
   The name of the scheduled task to create.
.PARAMETER StepNumber
   The step number to run in the Windows setup script.
.PARAMETER Description
   A description of the scheduled task.
#>
function Set-ScheduledTask {
    param (
        [Parameter(Mandatory=$true)][string]$TaskName,
        [Parameter(Mandatory=$true)][string]$StepNumber,
        [Parameter(Mandatory=$true)][string]$Description,
        [Parameter(Mandatory=$true)][string]$ScriptToRun
    )
    
    # Handle empty $PSScriptRoot
    if ([string]::IsNullOrEmpty($PSScriptRoot)) {
        $CurrentPath = Get-Location
    } else {
        $CurrentPath = $PSScriptRoot
    }
    
    $PathFile = (Join-Path $CurrentPath $ScriptToRun)
    $argumentString = "-NoProfile -File `"$PathFile`" -SetStepNumber $StepNumber"

    # Check for PowerShell Core
    if (Test-Path "C:\Program Files\PowerShell\7\pwsh.exe") {
        $action = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument $argumentString
    } else {
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $argumentString
    }

    # Create trigger and principal
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserID "$env:COMPUTERNAME\$env:USERNAME" -LogonType Interactive -RunLevel Highest

    # Register with correct hyphen
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $TaskName -Description $Description -Principal $principal -Force

    # Prompt for restart, with a bounded wait so this never hangs indefinitely when run
    # non-interactively (e.g. from the scheduled task itself)
    if (Confirm-RestartNow -TaskName $TaskName) {
        Restart-Computer
    } else {
        Write-Host "Please restart the computer manually to apply changes."
    }
}

<#
.SYNOPSIS
    Asks whether to restart now, with a bounded timeout so the caller is never blocked
    indefinitely.
.DESCRIPTION
    In a non-interactive session (no attached console), returns $true immediately so the
    unattended resume chain isn't stalled. In an interactive session, waits up to
    $TimeoutSeconds for a keypress: pressing 'N' cancels the restart, any other key (or no
    response within the timeout) proceeds with the restart. If the host doesn't support
    reading console key state at all, defaults to proceeding.
.PARAMETER TaskName
    The scheduled task name, used only in the prompt message.
.PARAMETER TimeoutSeconds
    How long to wait for a cancel keypress before proceeding. Defaults to 60 seconds.
.EXAMPLE
    if (Confirm-RestartNow -TaskName "WindowsSetup-Machine") { Restart-Computer }
#>
function Confirm-RestartNow {
    param(
        [Parameter(Mandatory = $true)][string]$TaskName,
        [int]$TimeoutSeconds = 60
    )

    if (-not [Environment]::UserInteractive) {
        Write-Host "Non-interactive session detected; proceeding with restart to apply `"$TaskName`"."
        return $true
    }

    try {
        Write-Host "A system restart is required to apply `"$TaskName`"."
        Write-Host "Press N within $TimeoutSeconds seconds to cancel the automatic restart. Any other key, or no response, continues with the restart."

        $stopwatch = [Diagnostics.Stopwatch]::StartNew()

        while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)

                if ($key.Key -eq 'N') {
                    Write-Host "Restart cancelled."
                    return $false
                }

                return $true
            }

            Start-Sleep -Milliseconds 200
        }

        Write-Host "No response received; proceeding with restart."
        return $true
    }
    catch {
        # Host doesn't support console key state (e.g. redirected input) - default to proceeding.
        return $true
    }
}

<#
.SYNOPSIS
    Pauses for a keypress before the console window closes, without hanging when run
    non-interactively or on a host that doesn't support reading console key state.
.PARAMETER Message
    The message to display before waiting. Defaults to a generic prompt.
.EXAMPLE
    Wait-ForKeyPress
#>
function Wait-ForKeyPress {
    param(
        [string]$Message = "Press any key to continue..."
    )

    if (-not [Environment]::UserInteractive) {
        return
    }

    try {
        Write-Host $Message
        $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
    }
    catch {
        # Host doesn't support RawUI.ReadKey (e.g. redirected/ISE) - no-op.
    }
}