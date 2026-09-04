<#
.SYNOPSIS
    Registers D365DevEnvMainMenu.ps1 as a global "D365DevEnvMainMenu" command.
.DESCRIPTION
    Creates a D365DevEnvMainMenu.cmd shim next to D365DevEnvMainMenu.ps1 and adds the repo
    folder to the current user's PATH environment variable, so typing "D365DevEnvMainMenu"
    in any terminal (cmd.exe, PowerShell 5, PowerShell 7) launches the menu. Idempotent -
    safe to call on every run; only writes/prints when something is actually missing.
#>
function Register-MainMenuCommand {
    $RepoPath  = Split-Path -Parent $PSScriptRoot
    $ShimPath  = Join-Path $RepoPath "D365DevEnvMainMenu.cmd"
    $Registered = $false

    if (-not (Test-Path $ShimPath)) {
        @'
@echo off
pwsh.exe -NoProfile -File "%~dp0D365DevEnvMainMenu.ps1" %*
'@ | Set-Content -Path $ShimPath -Encoding ASCII

        $Registered = $true
    }

    $UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    $PathEntries = @()
    if ($UserPath) {
        $PathEntries = $UserPath -split ';' | Where-Object { $_ }
    }

    $AlreadyOnPath = $PathEntries | Where-Object { $_.TrimEnd('\') -ieq $RepoPath.TrimEnd('\') }

    if (-not $AlreadyOnPath) {
        $NewUserPath = if ($UserPath) { "$UserPath;$RepoPath" } else { $RepoPath }
        [Environment]::SetEnvironmentVariable("PATH", $NewUserPath, "User")
        $env:PATH = "$env:PATH;$RepoPath"

        $Registered = $true
    }

    if ($Registered) {
        Write-Host "Registered 'D365DevEnvMainMenu' as a global command - open a new terminal to use it from anywhere." -ForegroundColor Green
    }
}
