param([string]$OutputDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root 'dist\ChomcioRecovery-v1.0.0-win-x64'}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Output already exists; choose a fresh directory.'}
$env:MSBuildEnableWorkloadResolver='false'
$artifacts=Join-Path $root 'artifacts\release'
foreach($entry in @(
 @{project='OneClickDesktop\ChomcioRecovery.Desktop.csproj';output=$OutputDirectory},
 @{project='ChomcioRecovery\src\ChomcioRecovery.Cli\ChomcioRecovery.Cli.csproj';output=(Join-Path $OutputDirectory 'cli')},
 @{project='SystemImageWorker\ChomcioRecovery.ImageWorker.csproj';output=(Join-Path $OutputDirectory 'image-worker\payload')}
)){
 & dotnet publish (Join-Path $root $entry.project) -c Release -r win-x64 --self-contained true --artifacts-path $artifacts -o $entry.output -m:1 -nr:false -p:UseSharedCompilation=false
 if($LASTEXITCODE -ne 0){throw 'Release build failed.'}
}
$worker=Join-Path $OutputDirectory 'image-worker'
$payload=Join-Path $worker 'payload'
$hashes=@(Get-ChildItem -LiteralPath $payload -File | Sort-Object Name | ForEach-Object {
 [ordered]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
})
[IO.File]::WriteAllText((Join-Path $payload 'package-hashes.json'),(ConvertTo-Json -InputObject $hashes),[Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath (Join-Path $root 'SystemImageWorker\Install-ImageWorker.ps1') -Destination $worker
Copy-Item -LiteralPath (Join-Path $root 'README.md') -Destination (Join-Path $OutputDirectory 'CZYTAJ_NAJPIERW.md')
Copy-Item -LiteralPath (Join-Path $root 'CHANGELOG.md') -Destination $OutputDirectory
Write-Output ('RELEASE_BUILD=PASS '+$OutputDirectory)
