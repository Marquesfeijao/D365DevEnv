$CurrentPath    = $PSScriptRoot
$FileName       = "taskLog.txt"
$LogPath        = Join-Path $CurrentPath "Logs"
$AddinPath      = Join-Path $CurrentPath "Addin"
$DeployPackages = Join-Path $CurrentPath "DeployablePackages"

function Install-Addin {
    Process {
        #Set-Location $AddinPath
        $repo = @("TrudAX/TRUDUtilsD365")
    
        $repo | ForEach-Object {
            $releases   = "https://api.github.com/repos/$_/releases"
            
            Write-Host ""
            Write-Host "Determining latest release for repo $_" -ForegroundColor Green
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $tag = (Invoke-WebRequest -Uri $releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name
        
            $files = @("InstallToVS.exe", "TRUDUtilsD365.dll", "TRUDUtilsD365.pdb")
            
            Write-Host ""
            Write-Host "Downloading files for repo $_" -ForegroundColor Cyan
            
            foreach ($file in $files) {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $download = "https://github.com/$_/releases/download/$tag/$file"
                Invoke-WebRequest $download -OutFile (join-path $AddinPath $file)
                Unblock-File (join-path $AddinPath $file)
            }
        
            Start-Process -FilePath (Join-Path $AddinPath "InstallToVS.exe") -WorkingDirectory $AddinPath -Verb runAs
        }
    }
}







Install-Addin