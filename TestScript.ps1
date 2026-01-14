function Show-ModelsTable {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $CurrentPath    = $PSScriptRoot

    # Load required assembly
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    if (-not (Test-Path $Path)) {
        [System.Windows.Forms.MessageBox]::Show("Path '$Path' does not exist.", "Error", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    # Create form
    $form                       = New-Object System.Windows.Forms.Form
    $form.Text                  = "Models Table"
    $form.Size                  = New-Object System.Drawing.Size(600,400)
    $form.StartPosition         = "CenterScreen"

    # Create DataGridView
    $dgv                        = New-Object System.Windows.Forms.DataGridView
    $dgv.Size                   = New-Object System.Drawing.Size(560,300)
    $dgv.Location               = New-Object System.Drawing.Point(10,10)
    $dgv.AutoSizeColumnsMode    = "Fill"
    $dgv.AllowUserToAddRows     = $false
    $dgv.RowHeadersVisible      = $false

    # Add columns
    $colCheck                   = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $colCheck.HeaderText        = "Marked"
    $colCheck.FillWeight        = 15

    $dgv.Columns.Add($colCheck)

    $colText = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $colText.HeaderText         = "Models"
    $dgv.Columns.Add($colText)

    # Fill rows with items from path (e.g., file names)
    Get-ChildItem -Path $Path | ForEach-Object {
        $row = $dgv.Rows.Add($false, $_.Name)
    }

    # Add DataGridView to form
    $form.Controls.Add($dgv)

    function Sync-GridToXml {
        param (
            [Parameter(Mandatory=$true)]
            [System.Windows.Forms.DataGridView]$DataGridView,

            [Parameter(Mandatory=$true)]
            [string]$XmlPath
        )

        try {
            # 1. Resolve absolute path to ensure correct saving location
            $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($XmlPath)

            # 2. Initialize XML Document
            $xmlDoc = New-Object System.Xml.XmlDocument

            if (Test-Path $fullPath) {
                # Load existing file
                $xmlDoc.Load($fullPath)
                
                # basic validation to ensure root exists
                if ($xmlDoc.SelectSingleNode("Models") -eq $null) {
                    Write-Warning "Invalid XML format. Recreating root."
                    $root = $xmlDoc.CreateElement("Models")
                    $xmlDoc.AppendChild($root) | Out-Null
                }
            }
            else {
                # Create new structure if file doesn't exist
                $declaration = $xmlDoc.CreateXmlDeclaration("1.0", "UTF-8", $null)
                $xmlDoc.AppendChild($declaration) | Out-Null
                $root = $xmlDoc.CreateElement("Models")
                $xmlDoc.AppendChild($root) | Out-Null
            }

            $rootNode = $xmlDoc.SelectSingleNode("Models")

            # 3. Collect the "Target State" from the DataGridView
            # We prefer a HashSet for faster lookups, containing only Marked items
            $markedModels = New-Object System.Collections.Generic.HashSet[string]

            foreach ($row in $DataGridView.Rows) {
                # Skip the "New Row" placeholder at the bottom of grids
                if ($row.IsNewRow) { continue }

                # Safely retrieve cell values
                if ($row.Cells[0].Value -eq $true) {
                    $modelName = $row.Cells[1].Value.ToString()
                    $markedModels.Add($modelName) | Out-Null
                }
            }

            # 4. DELETE: Remove items from XML that are NOT in the Marked list
            # We convert to a standard array for iteration to avoid modification errors while looping
            $currentXmlNodes = @($rootNode.SelectNodes("ModelName"))

            foreach ($node in $currentXmlNodes) {
                if (-not $markedModels.Contains($node.InnerText)) {
                    $rootNode.RemoveChild($node) | Out-Null
                    Write-Verbose "Deleted: $($node.InnerText)"
                }
            }

            # 5. ADD: Add items from Marked list that are NOT in the XML
            foreach ($model in $markedModels) {
                # Check if node already exists (Case insensitive check usually preferred)
                $existingNode = $rootNode.SelectSingleNode("ModelName[text()='$model']")
                
                if ($existingNode -eq $null) {
                    $newNode = $xmlDoc.CreateElement("ModelName")
                    $newNode.InnerText = $model
                    $rootNode.AppendChild($newNode) | Out-Null
                    Write-Verbose "Added: $model"
                }
            }

            # 6. Save the updated XML
            $xmlDoc.Save($fullPath)
            Write-Host "XML synchronization complete at: $fullPath" -ForegroundColor Green

        }
        catch {
            Write-Error "An error occurred syncing the XML: $_"
        }
    }



# Add Save button
    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text = "Save Marked"
    $btnSave.Size = New-Object System.Drawing.Size(100,30)
    $btnSave.Location = New-Object System.Drawing.Point(390,320)

    $btnSave.Add_Click({
        $marked = @()
        foreach ($row in $dgv.Rows) {
            if ($row.Cells[0].Value -eq $true) {
                $marked += [PSCustomObject]@{ Model = $row.Cells[1].Value }
            }
        }

        if ($marked.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No rows marked.", "Info", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Information)
        } else {
            $xmlPath = Join-Path $CurrentPath "MarkedModels.xml"
            #$marked | Export-Clixml -Path $xmlPath

            Sync-GridToXml -DataGridView $dgv -XmlPath $xmlPath
            
             [System.Windows.Forms.MessageBox]::Show("Saved to $xmlPath", "Success", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    })

    $form.Controls.Add($btnSave)


    # Add Close button
    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Close"
    $btnClose.Size = New-Object System.Drawing.Size(80,30)
    $btnClose.Location = New-Object System.Drawing.Point(490,320)
    $btnClose.Add_Click({ $form.Close() })
    $form.Controls.Add($btnClose)

    # Show form
    $form.Add_Shown({ $form.Activate() })
    [void]$form.ShowDialog()
}

Show-ModelsTable -Path "C:\AOSService\PackagesLocalDirectory"