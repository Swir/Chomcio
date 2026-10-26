param([Parameter(Mandatory=$true)][string]$PackageDirectory,[Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$source=Join-Path ([IO.Path]::GetFullPath($PackageDirectory)) 'image-worker\payload'
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Use a fresh test directory.'}
[IO.Directory]::CreateDirectory($OutputDirectory)|Out-Null
Get-ChildItem -LiteralPath $source -File|Copy-Item -Destination $OutputDirectory
$exe=Join-Path $OutputDirectory 'ChomcioRecovery.ImageWorker.exe'
$manifest=Join-Path $OutputDirectory 'package-hashes.json'
$original=[IO.File]::ReadAllText($manifest)
$records=$original|ConvertFrom-Json
$checks=0
function Check-Package([bool]$expected,[string]$label){
 # This mode only hashes package files; it cannot install or start capture.
 $process=Start-Process -FilePath $exe -ArgumentList '--check-package' -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput (Join-Path $OutputDirectory 'stdout.txt') -RedirectStandardError (Join-Path $OutputDirectory 'stderr.txt')
 if(($process.ExitCode -eq 0) -ne $expected){throw ('Worker manifest regression: '+$label)}
 $script:checks++
}
try{
 Check-Package $true 'original package'
 foreach($invalid in @('{}','null','[null]','[]',('{"value":'+$original+'}'))){
  [IO.File]::WriteAllText($manifest,$invalid);Check-Package $false 'non-array or missing records'
 }
 $duplicate=@($records)+@($records[0]);[IO.File]::WriteAllText($manifest,(ConvertTo-Json -InputObject $duplicate));Check-Package $false 'duplicate names'
 $missing=@($records|Where-Object name -ne 'ChomcioRecovery.ImageWorker.exe');[IO.File]::WriteAllText($manifest,(ConvertTo-Json -InputObject $missing));Check-Package $false 'required EXE omitted'
 foreach($name in @('../escape.dll','child\escape.dll','..','NUL','CON.txt','hostfxr.dll.')){
  $changed=$original|ConvertFrom-Json;$changed[0].name=$name
  [IO.File]::WriteAllText($manifest,(ConvertTo-Json -InputObject $changed));Check-Package $false 'unsafe member path'
 }
 $changed=$original|ConvertFrom-Json;$changed[0].sha256=('0'*64)
 [IO.File]::WriteAllText($manifest,(ConvertTo-Json -InputObject $changed));Check-Package $false 'changed expected hash'
 [IO.File]::WriteAllText($manifest,$original);Check-Package $true 'original restored'
 [pscustomobject]@{pass=$true;checks=$checks;publishedWorker=$true;mode='check-package';installed=$false;captureStarted=$false;timeUtc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Encoding UTF8
 Write-Output ('NATIVE_WORKER_PACKAGE=PASS checks='+$checks)
}finally{[IO.File]::WriteAllText($manifest,$original)}
