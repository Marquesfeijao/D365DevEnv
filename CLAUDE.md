# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A collection of PowerShell scripts that automate provisioning and maintenance of a Dynamics 365 Finance & Operations (D365FO) development VM: Windows setup, tool/app installation, SQL Server/database setup, bacpac import, service control, database sync, and cleanup of local model folders. There is no build system, package manifest, or test framework — this is operational tooling meant to be run directly on a Windows Server D365FO dev box (observed here as Windows Server 2022).

## Running scripts

- Entry point: `D365DevEnvMainMenu.ps1` — an interactive numbered menu that launches each task script in a new `pwsh.exe` window (`Start-Process pwsh.exe -ArgumentList "-NoProfile -File <script>"`). Run it with `pwsh.exe -NoProfile -File D365DevEnvMainMenu.ps1`.
- Individual scripts can also be run standalone, e.g. `pwsh.exe -NoProfile -File WindowsSetup.ps1 -SetStepNumber 3`.
- The menu checks for PowerShell 7 (`pwsh.exe`) first and offers to install it (via `Install-Powershell7.psm1`) if missing — most scripts assume pwsh 7, not Windows PowerShell 5.
- There are no lint/build/test commands — verification is manual (run the relevant script on a dev VM).

## Step-driven scripts and reboot persistence

`WindowsSetup.ps1`, `InstallUpdateApps.ps1`, and `DBSetup.ps1` share one convention: each is a single file divided into `#region`-wrapped numbered steps (`if ($SetStepNumber -eq N) { ... }`), and the step ranges are partitioned across the three files so together they form one continuous provisioning sequence:

- `WindowsSetup.ps1` — steps 1–8 (default start: 1)
- `InstallUpdateApps.ps1` — steps 9–12 (default start: 9)
- `DBSetup.ps1` — steps 13–18 (default start: 13)

Each step: logs `StepStart`/`StepComplete`/`StepError` to `Logs\taskLog.txt` via a local `Write-Log` function (each script defines its own copy — there's no shared logging module in use, despite the empty `Write-Log.psm1` stub in the repo root), does its work, and on success increments `$SetStepNumber` before falling through to the next region. On failure the step number is reset back to itself so a re-run retries that step.

Because installs/updates in these steps often require a machine restart, `Set-ScheduledTask.psm1`'s `Set-ScheduledTask` registers an `AtLogOn` scheduled task that re-invokes the same script with `-SetStepNumber <next>` after reboot, then prompts the user to restart immediately. When editing these scripts, preserve this pattern: keep steps idempotent/resumable, keep step numbers unique and sequential across the three files, and keep the try/catch + `Write-Log` + step-increment shape consistent with existing steps.

## Script/module conventions

- Scripts resolve their own directory via `$CurrentPath = $PSScriptRoot` and build paths with `Join-Path` (or string concatenation) from there — don't assume the current working directory.
- Shared logic lives in root-level `.psm1` modules imported with `Import-Module "$PSScriptRoot\X.psm1" -DisableNameChecking`: `Set-ScheduledTask.psm1` (reboot-resume tasks), `Install-Powershell7.psm1` (installs pwsh 7 from the latest GitHub release), `Clear-BCPTables.psm1` (strips rows from specific tables inside a bacpac before import).
- Most scripts end with `$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null` so the console window (opened via `Start-Process`) stays open for the user to read output before it closes.
- Interactive prompts use `$host.UI.PromptForChoice(...)` (see `PromptChoice` functions in `StartStopServices.ps1`, `Import-Bacpac.ps1`, `DeletingModelFolders.ps1`) rather than `Read-Host` for yes/no style choices.
- D365-specific SQL/bacpac operations depend on the `dbatools` and `d365fo.tools` PowerShell modules (installed/updated on demand, e.g. `Install-ModuleList` in `Import-Bacpac.ps1`). SQL Server instance is generally referenced as `.` (local default instance), database as `AxDB`.
- `DBSetup.ps1` and `Import-Bacpac.ps1` both raise/lower `sql.connection.trustcert` and SQL Server max-memory (`Set-DbaMaxMemory`, scaled by a percentage of total physical memory) around heavy operations — bump memory up before bulk import/index work, restore it afterward, including in `catch`/`finally` blocks.
- `DBSetup.ps1`'s step 16 and `D365FODatabaseSync.ps1` contain destructive/production-affecting SQL (table truncation, purges, full DB sync) — treat changes to this SQL with extra care and don't broaden what gets truncated/dropped without being asked.
- `D365FODatabaseSync.ps1` hardcodes SQL credentials (`SqlUser`/`SqlPassword`) inline — be aware this is a dev-VM-only script, not a pattern to replicate elsewhere in the repo.

## Other things to know

- `MarkedModels.xml` and `TestScript.ps1` (`Show-ModelsTable`) support a WinForms UI for marking which models to keep/delete; `DeletingModelFolders.ps1` deletes a hardcoded `$ModelDelete` list of model folders under `C:\AOSService\PackagesLocalDirectory` and stops/starts D365FO services around the deletion via `StartStopServices.ps1`.
- `Addin`, `DeployablePackages`, `Logs`, `__blobstorage__`, and the `__azurite_db_blob__*` files are runtime/working directories and local Azurite storage emulator state, not source — don't treat their contents as part of the script logic.
