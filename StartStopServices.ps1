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
<#
.SYNOPSIS
Handles the process of starting or stopping services based on the provided status.

.DESCRIPTION
The `ServiceProcess` function accepts a status parameter and performs actions 
to either start or stop services. It outputs the current status of the process 
to the console with a cyan foreground color.

.PARAMETER Status
Specifies the desired action for the service process. 
Accepted values are:
- "Start": Initiates the process of starting services.
- "Stop": Initiates the process of stopping services.

.EXAMPLE
ServiceProcess -Status "Start"
This example starts the services and displays the message "****** Status: Starting services... ******" in cyan.

.EXAMPLE
ServiceProcess -Status "Stop"
This example stops the services and displays the message "****** Status: Stopping services... ******" in cyan.

.NOTES
Ensure that the `Status` parameter is provided and contains a valid value ("Start" or "Stop").
The function does not perform actual service operations; it only outputs the status message.
#>
function ServiceProcess {
    param (
            [Parameter(Mandatory=$true, HelpMessage="Show the status of the service process.")]
            [string]$Status
        )
    switch ($Status) {
        "Stop" { 
            $Process = "Stopping services..."
        }
        "Start" { 
            $Process = "Starting services..."
        }
    }

    Write-Host "****** Status: $Process ******" -ForegroundColor "Cyan"
}

<#
.SYNOPSIS
    Prompts the user to choose whether to start or stop services and executes the corresponding action.

.DESCRIPTION
    This function provides an interactive prompt for the user to select whether to start or stop services related to Dynamics 365FO.
    If no status is provided, the user is prompted to make a choice. Based on the choice, the function executes the appropriate action.

.PARAMETER Status
    Optional parameter to specify the desired action ("Start" or "Stop"). If not provided, the user is prompted to choose.

.EXAMPLE
    PromptChoice -Status "Start"
    This will start the services without prompting the user.

.EXAMPLE
    PromptChoice
    This will prompt the user to choose whether to start or stop the services.

.NOTES
    The function uses the host's UI to display a choice prompt if no status is provided.
#>
function PromptChoice {
    param (
        [Parameter(Mandatory=$false, HelpMessage="Specify 'Start' or 'Stop' to control the services. If omitted, the user will be prompted.")]
        [string]$Status
    )

    # If no status is provided, prompt the user for a choice
    if ([string]::IsNullOrWhiteSpace($Status)) {
        $Title   = "Do you want to start or stop the services?"
        $Prompt  = "Enter your choice"
        $Choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Start", "S&top")
        $Default = 1 # Default choice is "Stop"

        # Prompt for the choice
        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)
        switch ($Choice) {
            0 { $Status = "Start" } # Start
            1 { $Status = "Stop" }  # Stop
        }
    }

    # Execute the action based on the status
    switch ($Status) {
        "Stop" { 
            ServiceProcess -Status $Status
            StartStopStatus -ServerStatus $Status
        }
        "Start" { 
            ServiceProcess -Status $Status
            StartStopStatus -ServerStatus $Status
        }
        default {
            Write-Host "Invalid status provided. Please specify 'Start' or 'Stop'." -ForegroundColor Red
        }
    }
}

function ElapsedTime($TaskStartTime) {
    $ElapsedTime = New-TimeSpan $TaskStartTime $(Get-Date)

    Write-Host "Elapsed time:$($ElapsedTime.ToString("hh\:mm\:ss"))" -ForegroundColor "Cyan"
}

<#
.SYNOPSIS
Controls the status of specified services by starting or stopping them.

.DESCRIPTION
The `StartStopStatus` function manages the status of a set of predefined services. 
It accepts a parameter to either start or stop the services. If an invalid status 
is provided, it displays an error message.

.PARAMETER ServerStatus
Specifies the desired status for the services. Acceptable values are:
- "Start": Starts the services that are not already running.
- "Stop": Stops the services that are not already stopped.

.EXAMPLE
StartStopStatus -ServerStatus "Start"
Starts the specified services that are not currently running and performs an IIS reset.

.EXAMPLE
StartStopStatus -ServerStatus "Stop"
Stops the specified services that are not currently stopped.

.NOTES
- The function uses `Get-Service` to retrieve the status of services and `Start-Service` 
    or `Stop-Service` to control them.
- The IIS reset is performed only when the services are started.
- Error handling is implemented to silently continue on errors during service control operations.
#>
function StartStopStatus {
    param (
        [Parameter(Mandatory=$true, HelpMessage="Specify 'Start' or 'Stop' to control the services.")]
        [string]$ServerStatus
    )

    switch ($ServerStatus) {
        "Stop" { 
            Get-Service -Name DocumentRoutingService, 
                        DynamicsAxBatch, 
                        'Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe',
                        W3SVC,
                        MR2012ProcessService,
                        aspnet_state    
            | Where-Object { $_.Status -ne 'Stopped' } | Stop-Service -ErrorAction SilentlyContinue -PassThru

            Write-Host "Services stopped successfully." -ForegroundColor Green
        }
        "Start" { 
            Get-Service -Name DocumentRoutingService, 
                        DynamicsAxBatch, 
                        'Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe',
                        W3SVC,
                        MR2012ProcessService,
                        aspnet_state    
            | Where-Object { $_.Status -ne 'Running' } | Start-Service -ErrorAction SilentlyContinue -PassThru

            Write-Host "Services started successfully." -ForegroundColor Green

            iisreset.exe
        }
        default {
            Write-Host "Invalid status provided. Please specify 'Start' or 'Stop'." -ForegroundColor Red
        }
    }
}
#endregion

PromptChoice -Status $ServiceStatus

Write-Host ""
ElapsedTime $ExecutionStartTime
Write-Host ""

$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null