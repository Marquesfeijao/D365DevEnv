<#
.SYNOPSIS
    Shared "install if missing, update if stale, then optionally import" logic for PowerShell
    Gallery modules, used across the provisioning scripts.
#>

Import-Module "$PSScriptRoot\Invoke-WithRetry.psm1" -DisableNameChecking

<#
.SYNOPSIS
    Installs a PowerShell Gallery module if missing, updates it if a newer version is
    published, and optionally imports it - retrying on transient failures.
.DESCRIPTION
    If the module is already installed, compares the installed version against the gallery's
    latest version and updates only if the gallery is newer. If not installed, installs it.
    The install/update attempt is wrapped in Invoke-WithRetry. Throws if the install/update
    ultimately fails, or if -Import is set and the import fails - callers decide whether that
    should be a hard failure (no local catch) or a soft warning (wrap the call in their own
    try/catch) depending on how critical the module is.
.PARAMETER Name
    The module name to install/update/import.
.PARAMETER Scope
    The install scope. Defaults to AllUsers.
.PARAMETER Import
    If set, imports the module after ensuring it's installed/up-to-date.
.PARAMETER MaxAttempts
    Maximum install/update attempts before giving up. Defaults to 3.
.EXAMPLE
    Install-OrUpdateModule -Name PSWindowsUpdate -Import
#>
function Install-OrUpdateModule {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$Scope = "AllUsers",
        [switch]$Import,
        [int]$MaxAttempts = 3
    )

    Invoke-WithRetry -OperationName "Install/update module $Name" -MaxAttempts $MaxAttempts -ScriptBlock {
        $installed = Get-Module -ListAvailable -Name $Name

        if ($installed) {
            $gallery        = Find-Module -Name $Name -ErrorAction SilentlyContinue
            $currentVersion = ($installed | Sort-Object Version -Descending | Select-Object -First 1).Version

            if ($gallery -and $gallery.Version -gt $currentVersion) {
                Write-Host "Updating module $Name from $currentVersion to $($gallery.Version)"
                Update-Module -Name $Name -Force -Scope $Scope -ErrorAction Stop
            }
            else {
                Write-Host "Module $Name is up-to-date (version $currentVersion)"
            }
        }
        else {
            Write-Host "Installing module $Name"
            Install-Module -Name $Name -SkipPublisherCheck -Scope $Scope -AllowClobber -Force -ErrorAction Stop
        }
    }

    if ($Import) {
        Import-Module -Name $Name -Force -ErrorAction Stop
    }
}
