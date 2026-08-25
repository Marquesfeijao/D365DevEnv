<#
.SYNOPSIS
    Stops D365FO services and deletes a hardcoded list of model folders from PackagesLocalDirectory.

.DESCRIPTION
    Stops the D365FO services via StartStopServices.ps1, then removes each folder named in
    $ModelDelete from under $RootPath. After the deletions complete, prompts the user to choose
    whether to start the services back up.

.NOTES
    The list of models to delete ($ModelDelete) is hardcoded in this script rather than being
    parameterized. Update it directly when the set of models to remove changes.
#>
$RootPath      = "C:\AOSService\PackagesLocalDirectory"
$ModelDelete = @("ALLCommon"
                 ,"ALLCommonIntegration"
                 ,"ALLFoundation"
                 ,"ALLOneStream"
                 ,"ALLReports"
				     ,"ATS"
				     ,"ATSFileTransferConnector"
                 ,"BssiAdvancedSubscriptionManagement"
                 ,"BssiCommon"
				     ,"DMSConnector"
				     ,"DocentricAX"
				     ,"DocentricAXEmails"
				     ,"DocentricAXExtension"
				     ,"DocentricAXSSRSReplicas"
				     ,"DocentricAXWarehouseLabels"
				     ,"FileTransferSuite")

<#
.SYNOPSIS
    Prompts the user to start the D365FO services and starts them if confirmed.

.DESCRIPTION
    Displays a Yes/No console prompt asking whether to start the services. If the user
    chooses "Yes", invokes StartStopServices.ps1 with -ServerStatus Start; otherwise takes
    no action.

.EXAMPLE
    PromptChoice
#>
function PromptChoice {

   $Title   = "Do you want to start the services?"
   $Prompt  = "Enter your choice"
   $Choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
   $Default = 1

   # Prompt for the choice
   $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)

   # Action based on the choice
   switch($Choice)
   {
      0 { 
         $ScriptToRun = $PSScriptRoot + ".\StartStopServices.ps1" 
         &$ScriptToRun  -ServerStatus Start
         Write-Host ""
      }
      1 { Write-Host "No"}
   }
}

$ScriptToRun = $PSScriptRoot + ".\StartStopServices.ps1" 
&$ScriptToRun  -ServiceStatus Stop

Write-Host ""
Write-Host "Starting deleting folders:"  -ForegroundColor "White"
Write-Host ""

$ModelDelete = $ModelDelete | ForEach-Object { 
     Write-Host " Deleting Folder: $_"
     try {
        Remove-Item -Path "$RootPath\$_" -Recurse -Force -ErrorAction Stop
     }
     catch {
        Write-Host " Error in deleting folder: $_"
                    Write-Host "Error message: " + $_.Exception.Message
     }
}

Write-Host ""
Write-Host "Finished deleting process:"  -ForegroundColor "White"
Write-Host ""

PromptChoice