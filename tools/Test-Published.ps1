param([Parameter(Mandatory=$true)][string]$PackageDirectory,[Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$PackageDirectory=[IO.Path]::GetFullPath($PackageDirectory)
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Use a fresh test directory.'}
$cli=Join-Path $PackageDirectory 'cli\ChomcioRecovery.Cli.exe'
if(-not(Test-Path -LiteralPath $cli)){throw 'Published CLI missing.'}
$version=(Get-Item -LiteralPath (Join-Path $PackageDirectory 'ChomcioRecovery.exe')).VersionInfo.FileVersion
if($version -ne '1.0.0.0'){throw 'Unexpected desktop version.'}
[IO.Directory]::CreateDirectory($OutputDirectory)|Out-Null
$source=Join-Path $OutputDirectory 'source';$repo=Join-Path $OutputDirectory 'vault';$restore=Join-Path $OutputDirectory 'restored'
[IO.Directory]::CreateDirectory((Join-Path $source 'empty'))|Out-Null
[IO.File]::WriteAllText((Join-Path $source 'zażółć.txt'),'Chomcio v1 - synthetic release check',[Text.Encoding]::UTF8)
[IO.File]::WriteAllBytes((Join-Path $source 'bytes.bin'),[Security.Cryptography.RandomNumberGenerator]::GetBytes(65537))
$password=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$checks=0
function Run-Cli([string[]]$Arguments,[bool]$ShouldSucceed=$true,[string]$Secret=$password){
 $start=[Diagnostics.ProcessStartInfo]::new($cli)
 $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 foreach($argument in $Arguments){$start.ArgumentList.Add($argument)}
 $start.Environment['CHOMCIO_PASSWORD']=$Secret
 $process=[Diagnostics.Process]::Start($start)
 try{
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  $process.WaitForExit();$output=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
  if(($process.ExitCode -eq 0) -ne $ShouldSucceed){throw ('Published CLI check failed: '+$Arguments[0])}
  $script:checks++
  return $output
 }finally{$process.Dispose()}
}
$null=Run-Cli @('init',$repo)
$backup=Run-Cli @('backup',$repo,$source)
if($backup -notmatch 'SNAPSHOT=([a-f0-9]{32})'){throw 'Snapshot result missing.'}
$snapshot=$matches[1]
$null=Run-Cli @('verify',$repo,$snapshot)
$null=Run-Cli @('restore',$repo,$snapshot,$restore)
foreach($name in @('zażółć.txt','bytes.bin')){
 if((Get-FileHash -LiteralPath (Join-Path $source $name)).Hash -ne (Get-FileHash -LiteralPath (Join-Path $restore $name)).Hash){throw 'Restored bytes differ.'}
 $checks++
}
if(-not(Test-Path -LiteralPath (Join-Path $restore 'empty') -PathType Container)){throw 'Empty directory missing.'};$checks++
$null=Run-Cli @('restore',$repo,$snapshot,$restore) $false
$null=Run-Cli @('verify',$repo,$snapshot) $false 'wrong-synthetic-release-password'
$portable=Join-Path $OutputDirectory 'portable'
$null=Run-Cli @('export',$repo,$snapshot,$portable)
$null=Run-Cli @('verify',$portable,$snapshot)
$report=[pscustomobject]@{pass=$true;version=$version;checks=$checks;actualPublishedExecutable=$true;syntheticOnly=$true;cloudOperations=0;systemImages=0;virtualMachinesStarted=0;timeUtc=[DateTime]::UtcNow.ToString('o')}
$report|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $OutputDirectory 'result.json') -Encoding UTF8
$password=$null
$report|ConvertTo-Json
