<#
    .SYNOPSIS
        Clears data from specified tables in a bacpac file.

    .DESCRIPTION
        This function takes a bacpac file and a list of table names, and removes all data from those tables within the bacpac file. It creates an updated version of the bacpac file with the specified tables cleared.

    .PARAMETER BCPFilePath
        The path to the directory containing the bacpac file.

    .PARAMETER BCPFileName
        The name of the bacpac file to be modified.

    .PARAMETER Tables
        A comma-separated string of table names to be cleared from the bacpac file.

    .EXAMPLE
        Clear-BCPTables -BCPFilePath "C:\Bacpacs" -BCPFileName "MyDatabase.bacpac" -Tables "Table1,Table2,Table3"
        Clears data from Table1, Table2, and Table3 in the specified bacpac file.

    .NOTES
        - Requires the d365fo.tools PowerShell module for the Clear-D365BacpacTableData cmdlet.
        - The function creates a new bacpac file with "_updated" appended to the original filename.

    .OUTPUTS
        None. The function modifies the bacpac file but does not return output.
#>
function Clear-BCPTables {
    param(
        [Parameter(Mandatory = $true)][string]$BCPFilePath,
        [Parameter(Mandatory = $true)][string]$BCPFileName,
        [Parameter(Mandatory = $true)][string]$Tables
    )

    Process {
        $BCPFile            = (Join-Path -Path $BCPFilePath $BCPFileName)
        $BCPFileUpdatedPath = (Join-Path -Path $BCPFilePath "BCPFile_updated.bacpac")

        $Tables = $Tables.Trim()
        $Tables = $Tables.Replace('"', '')
        $TableList = $Tables.Split(",")

        $TableList = $TableList | ForEach-Object { 
            if (-not ($_ -like "dbo*" -or $_ -like "*.*")) {
                "dbo." + $_
            }
        }

        try {
            if (Test-Path -Path $BCPFileUpdatedPath) {
                Remove-Item -Path $BCPFileUpdatedPath -Force    
            }

            Clear-D365BacpacTableData -Path $BCPFile -Table $TableList -OutputPath $BCPFileUpdatedPath
            
            Write-Host "Specified tables have been cleared from the BCP file." -ForegroundColor Green

            return $BCPFileUpdatedPath
        }
        catch {
            Remove-Item -Path $BCPFileUpdatedPath -Force
            Write-Warning "Error while updating BCP file: " + $_.Exception.Message
        }
    }
}