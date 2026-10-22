param(
    [Parameter(Mandatory=$true)][string]$PackagePath,
    [Parameter(Mandatory=$true)][string]$OwnerSid,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z]:\\$')][string]$DedicatedTarget,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{32}$')][string]$PlanId,
    [switch]$ProbeOnly
)
$ErrorActionPreference='Stop'
function Read-WorkerManifest([string]$PackageDirectory){
    $entries=Get-Content -LiteralPath (Join-Path $PackageDirectory 'package-hashes.json') -Raw|ConvertFrom-Json
    # Windows PowerShell can reserialize JSON arrays as {value: [...], Count: N}.
    # Never let missing names/hashes compare as null and pass a directory check.
    if($entries -isnot [array] -or $entries.Length -lt 4 -or $entries.Length -gt 1024){throw 'Package manifest must contain file records.'}
    $seen=@{}
    foreach($entry in $entries){
        if($entry.name -isnot [string] -or $entry.name -notmatch '^[A-Za-z0-9._-]+$' -or $entry.name -in @('.','..') -or
           $entry.sha256 -isnot [string] -or $entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or $seen.ContainsKey($entry.name)){throw 'Invalid package record.'}
        $seen[$entry.name]=$true
        $member=Join-Path $PackageDirectory $entry.name
        if(-not(Test-Path -LiteralPath $member -PathType Leaf)){throw 'Package member is not a file.'}
        if((Get-Item -LiteralPath $member).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Package contains a link.'}
        if((Get-FileHash -LiteralPath $member -Algorithm SHA256).Hash -ne $entry.sha256){throw 'Package hash mismatch.'}
    }
    foreach($required in @('ChomcioRecovery.ImageWorker.exe','ChomcioRecovery.ImageWorker.dll','ChomcioRecovery.ImageWorker.deps.json','ChomcioRecovery.ImageWorker.runtimeconfig.json')){
        if(-not $seen.ContainsKey($required)){throw 'Required worker file is missing.'}
    }
    return $entries
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator approval is required.'}
$owner=[Security.Principal.SecurityIdentifier]::new($OwnerSid)
if(-not $owner.IsAccountSid()){throw 'An individual Windows account is required.'}
$target=[IO.Path]::GetFullPath($DedicatedTarget)
if($target -eq [IO.Path]::GetPathRoot($env:windir)){throw 'System volume cannot be a backup target.'}
$volume=Get-Volume -DriveLetter $target.Substring(0,1)
if($volume.FileSystem -ne 'NTFS' -or $volume.DriveType -ne 'Fixed'){throw 'A dedicated local NTFS volume is required.'}
$systemVolume=Get-Volume -DriveLetter ([IO.Path]::GetPathRoot($env:windir).Substring(0,1))
if($volume.UniqueId -eq $systemVolume.UniqueId){throw 'Source and target volumes must differ.'}
$existing=@(Get-ChildItem -LiteralPath $target -Force | Where-Object {$_.Name -notin @('System Volume Information','$RECYCLE.BIN')})
if($existing.Count -ne 0){throw 'Dedicated target must be empty. Existing data is never removed or adopted.'}
$package=[IO.Path]::GetFullPath($PackagePath)
$files=@(Read-WorkerManifest $package)
$install=Join-Path $env:ProgramFiles 'ChomcioRecovery\ImageWorker'
$broker=Join-Path $env:ProgramData 'ChomcioRecovery\ImageBroker'
$taskName='ChomcioRecovery Image Broker'
if((Test-Path -LiteralPath $install) -or (Test-Path -LiteralPath $broker) -or (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)){throw 'Existing installation requires an explicit upgrade; refusing overwrite.'}
function Protect([string]$Path,[string]$ReaderSid,[bool]$Writable=$false){
    if((Test-Path -LiteralPath $Path) -and ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Installation path contains a link.'}
    if(-not(Test-Path -LiteralPath $Path)){New-Item -ItemType Directory -Path $Path | Out-Null}
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544');$acl.SetOwner($admins)
    foreach($sid in @($admins,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    if($ReaderSid){
        $rights=if($Writable){'Modify'}else{'ReadAndExecute'}
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($ReaderSid),$rights,'ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
# Parent directories are created only when absent; an unknown existing parent is
# rejected instead of changing permissions on unrelated software/data.
foreach($parent in @((Split-Path $install),(Split-Path $broker))){
    if(Test-Path -LiteralPath $parent){throw 'Parent installation directory already exists; manual upgrade required.'}
    Protect $parent 'S-1-5-11'
}
Protect $install 'S-1-5-11'
Protect $broker 'S-1-5-11'
Protect (Join-Path $broker 'plans') 'S-1-5-11'
$planDirectory=Join-Path $broker ('plans\'+$PlanId)
Protect $planDirectory $OwnerSid
Protect (Join-Path $planDirectory 'requests') $OwnerSid $true
Protect (Join-Path $planDirectory 'states') $OwnerSid
# Explicit dedicated-volume enrollment: no format, no cleanup, no host shutdown.
Protect $target $OwnerSid
# Only this cache subtree is writable by the unelevated owner. Its protected
# parent prevents replacement of the root; no capture worker writes inside it.
$cacheParent=Join-Path $target 'ChomcioRecoveryCache'
Protect $cacheParent $OwnerSid
$cache=Join-Path $cacheParent $PlanId
Protect $cache $OwnerSid
$cacheAcl=Get-Acl -LiteralPath $cache
$cacheAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($owner,'ReadAndExecute, Write, DeleteSubdirectoriesAndFiles','None','None','Allow'))
$cacheAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($owner,'Modify','ContainerInherit,ObjectInherit','InheritOnly','Allow'))
Set-Acl -LiteralPath $cache -AclObject $cacheAcl
foreach($item in $files){
    Copy-Item -LiteralPath (Join-Path $package $item.name) -Destination (Join-Path $install $item.name)
    if((Get-FileHash -LiteralPath (Join-Path $install $item.name) -Algorithm SHA256).Hash -ne $item.sha256){throw 'Installed binary mismatch.'}
}
$plan=[ordered]@{Version=1;PlanId=$PlanId;OwnerSid=$OwnerSid;TargetVolume=$volume.Path;SourceVolume=$systemVolume.Path;MachineName=$env:COMPUTERNAME}
[IO.File]::WriteAllText((Join-Path $planDirectory 'plan.json'),($plan | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
$arguments=if($ProbeOnly){'--probe'}else{'--serve'}
$action=New-ScheduledTaskAction -Execute (Join-Path $install 'ChomcioRecovery.ImageWorker.exe') -Argument $arguments -WorkingDirectory $install
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
$trigger=New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Trigger $trigger | Out-Null
# Lock task updates/deletion to administrators and SYSTEM; ordinary clients only
# submit small data requests in their own ACL-restricted queue.
$scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect()
$task=$scheduler.GetFolder('\').GetTask($taskName)
$task.SetSecurityDescriptor('D:P(A;;FA;;;SY)(A;;FA;;;BA)',0)
Start-ScheduledTask -TaskName $taskName
[pscustomobject]@{installed=$true;planId=$PlanId;probeOnly=[bool]$ProbeOnly;nativeBackupRequested=$false} | ConvertTo-Json -Compress
