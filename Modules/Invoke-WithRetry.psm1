<#
.SYNOPSIS
    Shared retry-with-backoff and non-destructive TLS setup helpers for network/install calls
    used across the provisioning scripts.
#>

Import-Module "$PSScriptRoot\Write-Log.psm1" -DisableNameChecking

<#
.SYNOPSIS
    Runs a scriptblock, retrying with a delay on failure, up to a maximum number of attempts.
.DESCRIPTION
    Invokes $ScriptBlock. If it throws, waits $DelaySeconds and retries, up to $MaxAttempts
    total attempts. On the final failed attempt, the exception is rethrown so the caller (e.g.
    Invoke-SetupStep) still sees the failure. Returns whatever $ScriptBlock returns on success.
.PARAMETER ScriptBlock
    The operation to attempt.
.PARAMETER MaxAttempts
    The maximum number of attempts before giving up. Defaults to 3.
.PARAMETER DelaySeconds
    How long to wait between attempts. Defaults to 15 seconds.
.PARAMETER OperationName
    A short label used in the retry/failure messages.
.PARAMETER LogPath
    Optional path to the log directory. When supplied together with -FileName, retry warnings
    and the final failure are also written to the log file via Write-Log (in addition to the
    console), not just shown on console.
.PARAMETER FileName
    Optional log file name, used together with -LogPath.
.EXAMPLE
    Invoke-WithRetry -OperationName "SSMS download" -ScriptBlock { $WebClient.DownloadFile($URL, $Filepath) }
.EXAMPLE
    Invoke-WithRetry -OperationName "SSMS download" -LogPath $LogPath -FileName $FileName -ScriptBlock { $WebClient.DownloadFile($URL, $Filepath) }
#>
function Invoke-WithRetry {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 15,
        [string]$OperationName = "operation",
        [string]$LogPath,
        [string]$FileName
    )

    $CanLog = -not [string]::IsNullOrEmpty($LogPath) -and -not [string]::IsNullOrEmpty($FileName)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $ScriptBlock
        }
        catch {
            if ($attempt -ge $MaxAttempts) {
                $FailureMessage = "$OperationName failed after $MaxAttempts attempts`: $($_.Exception.Message)"

                if ($CanLog) {
                    Write-Log -Level Error -Message $FailureMessage -LogPath $LogPath -FileName $FileName
                } else {
                    Write-Host $FailureMessage
                }

                throw
            }

            $RetryMessage = "$OperationName failed (attempt $attempt of $MaxAttempts): $($_.Exception.Message). Retrying in $DelaySeconds seconds..."

            if ($CanLog) {
                Write-Log -Level Warning -Message $RetryMessage -LogPath $LogPath -FileName $FileName
            } else {
                Write-Host $RetryMessage
            }

            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

<#
.SYNOPSIS
    Ensures the given TLS protocol is enabled on ServicePointManager without disabling any
    other protocol that may already be configured.
.PARAMETER Protocol
    The protocol to ensure is enabled. Defaults to Tls12.
.EXAMPLE
    Set-TlsSecurityProtocol
#>
function Set-TlsSecurityProtocol {
    param(
        [Net.SecurityProtocolType]$Protocol = [Net.SecurityProtocolType]::Tls12
    )

    if (-not ([Net.ServicePointManager]::SecurityProtocol.HasFlag($Protocol))) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $Protocol
    }
}
