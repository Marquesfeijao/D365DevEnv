<#
.SYNOPSIS
    Writes a timestamped, leveled log entry to the specified log file (and echoes it to the
    console).
.DESCRIPTION
    Appends one line to the log file in the form "[yyyy-MM-dd HH:mm:ss] [LEVEL] <text>". For the
    step-lifecycle levels (StepStart/StepComplete/StepError), <text> is built from -StepNum and
    -Message (the step name, or on StepError the failure detail); for the generic levels
    (Info/Warning/Error) <text> is just -Message. Also writes the same line to the console via
    Write-Host, color-coded by level, so nothing is lost from the existing console experience.
.PARAMETER Level
    The log level: Info, Warning, Error (generic messages) or StepStart, StepComplete, StepError
    (step lifecycle). Defaults to Info.
.PARAMETER Message
    The message text. For step-lifecycle levels this is normally the step name (StepStart/
    StepComplete) or "<step name> failed: <exception message>" (StepError).
.PARAMETER StepNum
    The step number being logged. Required for the step-lifecycle levels.
.PARAMETER LogPath
    The path to the log directory.
.PARAMETER FileName
    The name of the log file.
.EXAMPLE
    Write-Log -Level Info -Message "Set up Nuget" -LogPath $LogPath -FileName $FileName
.EXAMPLE
    Write-Log -Level StepStart -StepNum 3 -Message "Configure Windows Update for Windows 10" -LogPath $LogPath -FileName $FileName
.EXAMPLE
    Write-Log -Level StepError -StepNum 4 -Message "Update PowerShell and help failed: $($_.Exception.Message)" -LogPath $LogPath -FileName $FileName
#>
function Write-Log {
    param (
        [ValidateSet("Info", "Warning", "Error", "StepStart", "StepComplete", "StepError")]
        [string]$Level = "Info",
        [string]$Message = "",
        [int]$StepNum,
        [Parameter(Mandatory=$true)][string]$LogPath,
        [Parameter(Mandatory=$true)][string]$FileName
    )

    try {
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        $Text = switch ($Level) {
            "StepStart"     { "Step $StepNum ($Message) started" }
            "StepComplete"  { "Step $StepNum ($Message) completed" }
            "StepError"     { "Step $StepNum $Message" }
            default         { $Message }
        }

        $LevelLabel = if ($Level -in @("StepStart", "StepComplete", "StepError")) { "INFO" } else { $Level.ToUpper() }
        if ($Level -eq "StepError") { $LevelLabel = "ERROR" }

        $Line = "[$Timestamp] [$LevelLabel] $Text"

        Write-Output $Line | Out-File (Join-Path $LogPath $FileName) -Append -Encoding utf8 -ErrorAction Stop

        $Color = switch ($LevelLabel) {
            "ERROR"     { "Red" }
            "WARNING"   { "Yellow" }
            default     { "Gray" }
        }

        Write-Host $Line -ForegroundColor $Color
    }
    catch {
        Write-Host "Failed to write log: $($_.Exception.Message)"
    }
}
