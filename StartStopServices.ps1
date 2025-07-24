<#
.SYNOPSIS
    Start and Stop services related with Dynamics 365FO

.DESCRIPTION
    This script is intended for use in the Dynamics AX Development stopping or starting services related.

.NOTES
    
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$false, HelpMessage="Start or stop the services related with Dynamics 365FO. Default behavior is stop the services.")]
    [string]$ServiceStatus
)

$ExecutionStartTime = $(Get-Date)
$TaskStartTime      = $(Get-Date)

#region Methods
function PromptChoice {
    param (
        [Parameter(Mandatory=$false)][string]$Status
    )

    if ($Status -eq "") {
        $Title   = "Do you want to start or stop the services?"
        $Prompt  = "Enter your choice"
        $Choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Start", "S&top")
        $Default = "1" # Default choice is "Stop"

        # Prompt for the choice
        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)
        switch ($Choice) {
            0 { $Status = "Start" } # Start
            1 { $Status = "Stop" }  # Stop
        }
    }

   # Action based on the choice
   switch ($Status) {
        "Stop" { 
            StartImport $(Get-Date)
            StopServices 
        }
        "Start" { 
            StartImport $(Get-Date)
            StartServices
        }
    }

}

function StartImport($StartProcess){
    Write-Host "****** Change services status ******" -ForegroundColor "Cyan"
}

function ElapsedTime($TaskStartTime) {
    $ElapsedTime        = New-TimeSpan $TaskStartTime $(Get-Date)

    Write-Host "Elapsed time:$($ElapsedTime.ToString("hh\:mm\:ss"))" -ForegroundColor "Cyan"
}

function Pause ($message) {
    # Check if running Powershell ISE
    if ($psISE) {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$message")
    }
    else {
        Write-Host "$message" -ForegroundColor Yellow
        $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

function StartServices(){
    Write-Host ""
    Write-Host "Starting services..." -ForegroundColor "White"
    Write-Host ""

    Get-Service DocumentRoutingService, 
                DynamicsAxBatch, 
                'Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe',
                W3SVC,
                MR2012ProcessService,
                aspnet_state    
    | Start-Service -ErrorAction Ignore -PassThru

    iisreset.exe
}

function StopServices(){
    Write-Host ""
    Write-Host "Stopping services..." -ForegroundColor "White"
    Write-Host ""

    Get-Service DocumentRoutingService, 
                DynamicsAxBatch, 
                'Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe',
                W3SVC,
                MR2012ProcessService,
                aspnet_state    
    | Stop-Service -ErrorAction Ignore -PassThru

}
#endregion

PromptChoice -Status $ServiceStatus

Write-Host ""
ElapsedTime $ExecutionStartTime
Write-Host ""
