$CurrentPath    = (Get-Location).Path

function Initialize-Setup{

    $registryPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    $name           = "Functions"
    $value          = $(Get-ItemProperty -Path $registryPath -Name $name).Functions
    #region Cipher
    $cipher         = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,"
    $cipher         += "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,"
    $cipher         += "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,"
    $cipher         += "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,"
    $cipher         += "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,"
    $cipher         += "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,"
    $cipher         += "TLS_RSA_WITH_AES_256_GCM_SHA384,"
    $cipher         += "TLS_RSA_WITH_AES_128_GCM_SHA256,"
    $cipher         += "TLS_RSA_WITH_AES_256_CBC_SHA256,"
    $cipher         += "TLS_RSA_WITH_AES_128_CBC_SHA256,"
    $cipher         += "TLS_RSA_WITH_AES_256_CBC_SHA,"
    $cipher         += "TLS_RSA_WITH_AES_128_CBC_SHA,"
    $cipher         += "TLS_AES_256_GCM_SHA384,"
    $cipher         += "TLS_AES_128_GCM_SHA256"
    #endregion
    
	if (($value -eq $cipher))
    {
        #Set-ItemProperty -Path $registryPath -Name $name -Value $cipher
 		$scriptPath = "C:\Temp\D365FODevEnv-Installer\WindowsSetup.ps1"
        $argumentString = "-NoProfile -File `"$scriptPath`" -SetStepNumber 1"
 
         # Creating the scheduled task
         $action     = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $argumentString
        # $scriptBlock = {

            # & pwsh.exe -NoProfile -File (Join-Path $CurrentPath "WindowsSetup.ps1") -SetStepNumber 1
        # }
        #& $scriptBlock $CurrentPath

        # Creating the scheduled task
        #$action     = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "$scriptBlock"
        $trigger    = New-ScheduledTaskTrigger -AtLogOn

        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "WindowsSetup-Machine" -Description "Update the cipher" -RunLevel Highest –Force
        
        # Restart the computer (uncomment in actual use)
        #Restart-Computer
    }
}

function Set-ScheduledTask {
    param (
        [Parameter(Mandatory=$true)][string]$TaskName,
        [Parameter(Mandatory=$true)][string]$StepNumber,
        [Parameter(Mandatory=$true)][string]$Description
    )

    $argumentString = "-NoProfile -File $CurrentPath -SetStepNumber $StepNumber"

    # Creating the scheduled task
    $action     = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $argumentString
    $trigger    = New-ScheduledTaskTrigger -AtLogOn

    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $TaskName -Description $Description -RunLevel Highest –Force

    # Prompt the user before restarting the computer to avoid unexpected interruption
    $restart = Read-Host "A system restart is required to apply cipher changes. Do you want to restart now? (Y/N)"
    
    # if the user confirms, restart the computer
    if ($restart -eq 'Y' -or $restart -eq 'y') {
        Restart-Computer
    } else {
        Write-Host "Please restart the computer manually to apply changes."
    }
}
Set-ScheduledTask -TaskName "WindowsSetup-Machine" -StepNumber 1 -Description "Update the cipher"
#Initialize-Setup

# # Initial actions
# Write-Host "Performing initial actions before reboot..."
# Write-Output "Performing initial actions before reboot..." | Out-File  C:\Users\localadmin\OneDrive\Library\D365DevEnv\D365DevEnv\taskLogShutdown.txt -Append
# # Command to run a script block upon reboot
# $scriptBlock = {
    
# 	Write-Host "This is the continuation after reboot."
# 	Write-Output "This is the continuation after reboot." | Out-File  C:\Users\localadmin\OneDrive\Library\D365DevEnv\D365DevEnv\taskLogStart.txt -Append
# 	#Stop-ScheduledTask -TaskName "DevScriptAfterReboot"
# 	Unregister-ScheduledTask -TaskName "DevScriptAfterReboot" -Confirm:$false
# }
# # Convert script block to a Base64 encoded string to pass it to the scheduled task
# $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock.ToString()))
# # Creating the scheduled task
# $action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-EncodedCommand $encodedCommand"
# $trigger = New-ScheduledTaskTrigger -AtStartup
# Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "DevScriptAfterReboot" -Description "My task to continue script execution after reboot" -User "SYSTEM"
# # Restart the computer (uncomment in actual use)
# Restart-Computer

#$LocalFolder = (Get-Location).Path
#
#write-host "LocalFolder: $LocalFolder"

#$Module2Service = $('d365fo.tools')
#
#Install-Module -Name "d365fo.tools" -SkipPublisherCheck -Scope AllUsers -AllowClobber -Force
#Import-Module "d365fo.tools"
#Get-D365EnvironmentSettings