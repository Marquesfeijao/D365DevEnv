# Initial actions
Write-Host "Performing initial actions before reboot..."
Write-Output "Performing initial actions before reboot..." | Out-File  C:\Users\localadmin\OneDrive\Library\D365DevEnv\D365DevEnv\taskLogShutdown.txt -Append
# Command to run a script block upon reboot
$scriptBlock = {
    
	Write-Host "This is the continuation after reboot."
	Write-Output "This is the continuation after reboot." | Out-File  C:\Users\localadmin\OneDrive\Library\D365DevEnv\D365DevEnv\taskLogStart.txt -Append
	#Stop-ScheduledTask -TaskName "DevScriptAfterReboot"
	Unregister-ScheduledTask -TaskName "DevScriptAfterReboot" -Confirm:$false
}
# Convert script block to a Base64 encoded string to pass it to the scheduled task
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptBlock.ToString()))
# Creating the scheduled task
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-EncodedCommand $encodedCommand"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "DevScriptAfterReboot" -Description "My task to continue script execution after reboot" -User "SYSTEM"
# Restart the computer (uncomment in actual use)
Restart-Computer

#$LocalFolder = (Get-Location).Path
#
#write-host "LocalFolder: $LocalFolder"

#$Module2Service = $('d365fo.tools')
#
#Install-Module -Name "d365fo.tools" -SkipPublisherCheck -Scope AllUsers -AllowClobber -Force
#Import-Module "d365fo.tools"
#Get-D365EnvironmentSettings