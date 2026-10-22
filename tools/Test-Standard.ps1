param([string]$OutputDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot
if(-not(Test-Path -LiteralPath (Join-Path $root 'ChomcioRecovery\tests\fixtures\reference_v1_expected.json'))){throw 'Synthetic interoperability fixtures are missing from the source package.'}
if(-not $OutputDirectory){$OutputDirectory=Join-Path $root ('artifacts\checks-'+[guid]::NewGuid().ToString('N'))}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Use a fresh check directory.'}
[IO.Directory]::CreateDirectory($OutputDirectory)|Out-Null
$env:MSBuildEnableWorkloadResolver='false'
$artifacts=Join-Path $root 'artifacts\checks-build'
foreach($suite in @('Core','Cloud','Studio')){
 $project=Join-Path $root ('ChomcioRecovery\tests\ChomcioRecovery.'+$suite+'.Smoke\ChomcioRecovery.'+$suite+'.Smoke.csproj')
 & dotnet build $project -c Release --artifacts-path $artifacts -m:1 -nr:false -p:UseSharedCompilation=false
 if($LASTEXITCODE -ne 0){throw ('Build failed: '+$suite)}
 $dll=Join-Path $artifacts ('bin\ChomcioRecovery.'+$suite+'.Smoke\release\ChomcioRecovery.'+$suite+'.Smoke.dll')
 $testArgs=@($dll)
 if($suite -eq 'Studio'){$testArgs+=Join-Path $OutputDirectory 'studio'}
 & dotnet @testArgs
 if($LASTEXITCODE -ne 0){throw ('Checks failed: '+$suite)}
}
Write-Output 'STANDARD_CHECKS=PASS (synthetic data; no cloud account, system image or VM)'
