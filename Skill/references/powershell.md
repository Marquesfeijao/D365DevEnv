# PowerShell Documentation (Comment-Based Help)

PowerShell uses "comment-based help": a `<# ... #>` block with dot-prefixed keyword sections, placed either as the first thing in a `.ps1` script (for script-level help) or immediately above/inside a `function` (for function-level help — PowerShell also accepts it as the first lines inside the function body, but placing it directly above the `function` keyword is the more common and readable convention, so prefer that unless the file already consistently does otherwise).

## Function template

```powershell
<#
.SYNOPSIS
    [One-line summary of what the function does.]

.DESCRIPTION
    [A fuller explanation — a sentence or two on behavior, side effects, or important context that doesn't fit in the synopsis.]

.PARAMETER ParamName
    [Description of the parameter.]

.EXAMPLE
    [A realistic invocation of the function.]
    [Optionally followed by a line describing what it does/outputs.]

.OUTPUTS
    [Type and description of what's returned/written to the pipeline.]

.NOTES
    [Optional: caveats, prerequisites, author context — only include if there's something genuinely worth flagging.]
#>
function Verb-Noun {
    param(
        [string]$ParamName
    )
    ...
}
```

Rules:
- `.SYNOPSIS` and `.DESCRIPTION` are always present. Keep `.SYNOPSIS` to one line; use `.DESCRIPTION` for the rest.
- One `.PARAMETER` block per parameter, named after the parameter (no `$` prefix in the section header). **Omit entirely** for a parameter-less function.
- Include at least one `.EXAMPLE`. For functions with several meaningfully different usages (e.g. optional switches that change behavior), add more than one `.EXAMPLE` block rather than cramming them into one.
- `.OUTPUTS` — include when the function returns or writes a meaningful value/object to the pipeline. **Omit** for functions that are purely side-effecting (e.g. just write to a log or file and return nothing).
- `.NOTES` is optional — only add it when there's a real caveat, prerequisite (e.g. "Requires admin privileges"), or authorship/versioning note worth surfacing. Don't pad it.
- Indent section content by 4 spaces under each dot-keyword, matching the template above.
- Use PowerShell's approved verb-noun naming awareness only to inform tone, not to rename the user's functions — document what's there.

## Script-level template

For a standalone `.ps1` script (not a function), the same block goes at the very top of the file, before any code:

```powershell
<#
.SYNOPSIS
    [One-line summary of what the script does.]

.DESCRIPTION
    [Fuller explanation of the script's purpose and behavior.]

.PARAMETER ParamName
    [Description — for script-level `param()` blocks declared at the top of the file.]

.EXAMPLE
    .\ScriptName.ps1 -ParamName Value

.NOTES
    [Optional caveats/prerequisites.]
#>
param(
    [string]$ParamName
)
...
```

## Writing good summaries

- `.SYNOPSIS` should say what the function *does*, in behavioral terms — "Finds and terminates orphaned worker processes older than a given age," not "Process function."
- Read the body to understand real behavior (what it queries, calls, mutates, or requires) rather than paraphrasing the name.
- Keep `.DESCRIPTION` genuinely additive to `.SYNOPSIS` — don't just restate it in more words.

## Fixing or standardizing existing help blocks

- Expand any minimal or malformed comment-based help (missing sections, no blank-line separation, single-paragraph dumps) into the structured template above.
- Add any missing section for content that exists in the code but isn't documented (e.g. a parameter added later with no `.PARAMETER` entry).
- If a description is stale relative to current behavior, correct it, and flag non-obvious corrections to the user so they can confirm your reading of intent.
- Only touch the `<# ... #>` help block itself — leave `[CmdletBinding()]`, attributes, and surrounding code untouched.
- Skip functions/scripts that already have complete, correctly structured help, unless the user asked to review/standardize the whole file.

## Example

**Input:**
```powershell
function Get-OrphanedProcesses {
    param(
        [int]$MinAgeMinutes = 60
    )
    ...
}
```

**Output:**
```powershell
<#
.SYNOPSIS
    Finds worker processes with no active parent that have been running longer than a given age.

.DESCRIPTION
    Scans running processes, identifies those whose parent process no longer exists, and returns
    the ones older than the specified threshold so they can be reviewed or terminated.

.PARAMETER MinAgeMinutes
    The minimum age, in minutes, a process must have been running to be considered orphaned. Defaults to 60.

.EXAMPLE
    Get-OrphanedProcesses -MinAgeMinutes 30

.OUTPUTS
    System.Diagnostics.Process[] — the matching orphaned processes.
#>
function Get-OrphanedProcesses {
    param(
        [int]$MinAgeMinutes = 60
    )
    ...
}
```
