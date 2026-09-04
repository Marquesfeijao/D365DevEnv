# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A collection of PowerShell scripts that automate provisioning and maintenance of a Dynamics 365 Finance & Operations (D365FO) development VM: Windows setup, tool/app installation, SQL Server/database setup, bacpac import, service control, database sync, and cleanup of local model folders. There is no build system, package manifest, or test framework — this is operational tooling meant to be run directly on a Windows Server D365FO dev box (observed here as Windows Server 2022).

## Running scripts

- Entry point: `D365DevEnvMainMenu.ps1` — an interactive numbered menu that launches each task script in a new `pwsh.exe` window (`Start-Process pwsh.exe -ArgumentList "-NoProfile -File <script>"`). Run it with `pwsh.exe -NoProfile -File D365DevEnvMainMenu.ps1`.
- Individual scripts can also be run standalone, e.g. `pwsh.exe -NoProfile -File WindowsSetup.ps1 -SetStepNumber 3`.
- The menu checks for PowerShell 7 (`pwsh.exe`) first and offers to install it (via `Modules\Install-Powershell7.psm1`) if missing — most scripts assume pwsh 7, not Windows PowerShell 5.
- There are no lint/build/test commands — verification is manual (run the relevant script on a dev VM).

## Step-driven scripts and reboot persistence

`WindowsSetup.ps1`, `InstallUpdateApps.ps1`, and `DBSetup.ps1` share one convention: each is a single file divided into `#region`-wrapped numbered steps (`if ($SetStepNumber -eq N) { ... }`), and the step ranges are partitioned across the three files so together they form one continuous provisioning sequence:

- `WindowsSetup.ps1` — steps 1–8 (default start: 1)
- `InstallUpdateApps.ps1` — steps 9–12 (default start: 9)
- `DBSetup.ps1` — steps 13–18 (default start: 13)

Each step: logs `StepStart`/`StepComplete`/`StepError` to `Logs\taskLog.txt` via the shared `Write-Log` function (`Modules\Write-Log.psm1`, imported by all three scripts with `Import-Module "$PSScriptRoot\Modules\Write-Log.psm1" -DisableNameChecking`), does its work, and on success increments `$SetStepNumber` before falling through to the next region. On failure the step number is reset back to itself so a re-run retries that step.

Because installs/updates in these steps often require a machine restart, `Modules\Set-ScheduledTask.psm1`'s `Set-ScheduledTask` registers an `AtLogOn` scheduled task that re-invokes the same script with `-SetStepNumber <next>` after reboot, then prompts the user to restart immediately. When editing these scripts, preserve this pattern: keep steps idempotent/resumable, keep step numbers unique and sequential across the three files, and keep the try/catch + `Write-Log` + step-increment shape consistent with existing steps.

## Script/module conventions

- Scripts resolve their own directory via `$CurrentPath = $PSScriptRoot` and build paths with `Join-Path` (or string concatenation) from there — don't assume the current working directory. The entry-point and task scripts (`D365DevEnvMainMenu.ps1`, `WindowsSetup.ps1`, `InstallUpdateApps.ps1`, `DBSetup.ps1`, `Import-Bacpac.ps1`, `StartStopServices.ps1`, `Download-FileSASLink.ps1`, `DeletingModelFolders.ps1`, `D365FODatabaseSync.ps1`, `TestScript.ps1`) live at the repo root; shared modules live under `Modules\` and config/data files under `Config\` (see below) — both one level down from `$PSScriptRoot` in every root-level script.
- Shared logic lives in `Modules\*.psm1`, imported with `Import-Module "$PSScriptRoot\Modules\X.psm1" -DisableNameChecking`: `Set-ScheduledTask.psm1` (reboot-resume tasks), `Install-Powershell7.psm1` (installs pwsh 7 from the latest GitHub release), `Clear-BCPTables.psm1` (strips rows from specific tables inside a bacpac before import), `Write-Log.psm1` (shared `Write-Log` step-logging function, see above), `Invoke-SetupStep.psm1`, `Invoke-WithRetry.psm1`, `Install-OrUpdateModule.psm1`, `Register-MainMenuCommand.psm1`. Modules that need to know the repo root (`Set-ScheduledTask.psm1`, `Register-MainMenuCommand.psm1`) resolve it as `Split-Path -Parent $PSScriptRoot` — a module's own `$PSScriptRoot` is `Modules\` itself, not the repo root, so this one-level-up step matters whenever these modules are edited or moved again.
- Most scripts end with `$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null` so the console window (opened via `Start-Process`) stays open for the user to read output before it closes.
- Interactive prompts use `$host.UI.PromptForChoice(...)` (see `PromptChoice` functions in `StartStopServices.ps1`, `Import-Bacpac.ps1`, `DeletingModelFolders.ps1`) rather than `Read-Host` for yes/no style choices.
- D365-specific SQL/bacpac operations depend on the `dbatools` and `d365fo.tools` PowerShell modules (installed/updated on demand, e.g. `Install-ModuleList` in `Import-Bacpac.ps1`). SQL Server instance is generally referenced as `.` (local default instance), database as `AxDB`.
- `DBSetup.ps1` and `Import-Bacpac.ps1` both raise/lower `sql.connection.trustcert` and SQL Server max-memory (`Set-DbaMaxMemory`, scaled by a percentage of total physical memory) around heavy operations — bump memory up before bulk import/index work, restore it afterward, including in `catch`/`finally` blocks.
- `DBSetup.ps1`'s step 16 and `D365FODatabaseSync.ps1` contain destructive/production-affecting SQL (table truncation, purges, full DB sync) — treat changes to this SQL with extra care and don't broaden what gets truncated/dropped without being asked.
- `D365FODatabaseSync.ps1` hardcodes SQL credentials (`SqlUser`/`SqlPassword`) inline — be aware this is a dev-VM-only script, not a pattern to replicate elsewhere in the repo.

## Bacpac model-repair JSON files

`Import-Bacpac.ps1` calls d365fo.tools' `Repair-D365BacpacModelFile` to strip elements from the exported bacpac model XML (`BCPModel.xml`) that are invalid when importing into a local Tier1 SQL Server. That cmdlet takes up to three optional instruction files, each with its own JSON shape (array of objects at the file root, `"` escaped as `\"`):

- `-PathRepairSimple` — array of `{ "Search": ..., "End": ... }` objects. `Search` and `End` are `-like` wildcard patterns; when a line matches `Search`, that line and every following line are dropped until one matches `End` (block removal, e.g. a whole multi-line `<Element>...</Element>`).
- `-PathRepairReplace` — array of `{ "Search": ..., "Replace": ... }` objects. `Search` is matched and substituted literally (`.Replace()`, no wildcards) on each line, e.g. blanking out a single self-closing `<Property .../>`.
- `-PathRepairQualifier` — adds a third `Qualifier` match condition on top of `Search`/`End` (not used by any file in this repo).

In this repo (both files live under `Config\`):
- `Config\RepairSimpleCustom.json` holds three `Search`/`End` pairs that remove `<Element Type="SqlPermissionStatement">` blocks granting `KillDatabaseConnection.Database` to `ms_db_configreader`, `ms_db_configwriter`, and `ms_uno_dev_writer` — the correct shape for `-PathRepairSimple`.
- `Config\RepairReplaceCustom.json` holds `Search`/`Replace` pairs that blank out stray self-closing `<Property .../>` elements that are invalid or unsupported on a local Tier1 target: `AutoDrop="True"`, `IsAutomaticIndexCompactionOn="True"`, and `QueryStoreCaptureMode="4"` (Query Store capture mode `CUSTOM`, which DacFx's on-prem deployment plan generator rejects with `"The option 4 for querystore query_capture_mode is not supported"` when importing bacpacs sourced from Azure SQL DB) — the correct shape for `-PathRepairReplace`.
- `Import-Bacpac.ps1` wires up both: `-PathRepairSimple $RepairSimple` (pointing at `Config\RepairSimpleCustom.json`) and `-PathRepairReplace $RepairReplace` (pointing at `Config\RepairReplaceCustom.json`), with `-PathRepairQualifier ''` to skip that unused third section. These two files replaced an earlier `SimpleKillConnection.json` that mixed both shapes in one file (which only worked because it was passed solely via `-PathRepairSimple`, silently ignoring its `Search`/`Replace`-shaped entries) — new repair rules should go in whichever of `RepairSimpleCustom.json` / `RepairReplaceCustom.json` matches the shape needed (block removal vs. single-line replace), not back into a merged file.

## Other things to know

- `DeletingModelFolders.ps1` deletes a hardcoded `$ModelDelete` list of model folders under `C:\AOSService\PackagesLocalDirectory` and stops/starts D365FO services around the deletion via `StartStopServices.ps1`.
- `TestScript.ps1` is a scratch/manual-test script (currently a standalone copy of `Install-Addin`, invoked immediately on run) — not part of the numbered step sequence and not wired into the main menu. `MarkedModels.xml` is likewise unreferenced by any script in the repo; both are leftovers from an earlier WinForms model-marking UI that no longer exists in the codebase.
- `Addin`, `DeployablePackages`, `Logs`, `__blobstorage__`, and the `__azurite_db_blob__*` files are runtime/working directories and local Azurite storage emulator state, not source — don't treat their contents as part of the script logic.
