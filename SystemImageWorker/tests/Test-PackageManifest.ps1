param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputDirectory){throw 'Use a new test directory.'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
$installer=Join-Path (Split-Path $PSScriptRoot) 'Install-ImageWorker.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($installer,[ref]$tokens,[ref]$errors)
if($errors.Count){throw $errors[0]}
$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Read-WorkerManifest'},$true)
if(-not $function){throw 'Manifest reader missing.'}
# Load only the pure package check; never execute the privileged installer.
. ([scriptblock]::Create($function.Extent.Text))
$records=@()
foreach($name in @('ChomcioRecovery.ImageWorker.exe','ChomcioRecovery.ImageWorker.dll','ChomcioRecovery.ImageWorker.deps.json','ChomcioRecovery.ImageWorker.runtimeconfig.json')){
    $path=Join-Path $OutputDirectory $name
    [IO.File]::WriteAllText($path,'synthetic package member: '+$name)
    $records+=[pscustomobject]@{name=$name;sha256=(Get-FileHash -LiteralPath $path).Hash}
}
$manifest=Join-Path $OutputDirectory 'package-hashes.json'
$validJson=ConvertTo-Json -InputObject $records
function Check([string]$label,[string]$json,[bool]$expected){
    Set-Content -LiteralPath $manifest -Value $json -Encoding UTF8
    $accepted=$true
    try{$loaded=@(Read-WorkerManifest $OutputDirectory);if($loaded.Length -ne 4){throw 'Wrong file count.'}}catch{$accepted=$false}
    if($accepted -ne $expected){throw ('Unexpected manifest result: '+$label)}
    Write-Output ('PASS: '+$label)
}
Check 'valid package' $validJson $true
Check 'PS5 array wrapper rejected' ('{"value":'+$validJson+',"Count":4}') $false
Check 'null fields rejected' '[{},{},{},{}]' $false
Check 'duplicate names rejected' (ConvertTo-Json -InputObject @($records[0],$records[0],$records[2],$records[3])) $false
Check 'missing required member rejected' (ConvertTo-Json -InputObject @($records[0],$records[1],$records[2])) $false
Check 'path traversal rejected' ($validJson.Replace('ChomcioRecovery.ImageWorker.dll','../outside.dll')) $false
Check 'missing file rejected' ($validJson.Replace('ChomcioRecovery.ImageWorker.dll','missing.dll')) $false
Check 'malformed hash rejected' ($validJson.Replace($records[0].sha256,'not-a-hash')) $false
Check 'changed bytes rejected' ($validJson.Replace($records[0].sha256,('0'*64))) $false
Check 'directory rejected' (ConvertTo-Json -InputObject @([pscustomobject]@{name='.';sha256=$records[0].sha256},$records[1],$records[2],$records[3])) $false
Check 'valid package still accepted' $validJson $true
