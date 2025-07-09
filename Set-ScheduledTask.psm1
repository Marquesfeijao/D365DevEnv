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
        [Parameter(Mandatory=$true)][string]$Description
    )
    
    $PathFile       = (Join-Path $CurrentPath "WindowsSetup.ps1")
    $argumentString = "-NoProfile -File $PathFile -SetStepNumber $StepNumber"

    if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) {
        $action = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument $argumentString
    } else {
        $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $argumentString
    }

    # Creating the scheduled task
    $trigger = New-ScheduledTaskTrigger -AtLogOn

    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $TaskName -Description $Description -RunLevel Highest –Force

    # Prompt the user before restarting the computer to avoid unexpected interruption
    $restart = Read-Host "A system restart is required to apply `"$TaskName`". Do you want to restart now? (Y/N)"
    
    # if the user confirms, restart the computer
    if ($restart -eq 'Y' -or $restart -eq 'y') {
        Restart-Computer
    } else {
        Write-Host "Please restart the computer manually to apply changes."
    }
}