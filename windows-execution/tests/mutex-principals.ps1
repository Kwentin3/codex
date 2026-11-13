[CmdletBinding()]
param(
    [string]$ExecutorPath=(Join-Path $env:USERPROFILE '.agents/windows-execution/agent-exec.v1.exe'),
    [string]$MutexAssembly
)
$ErrorActionPreference='Stop'
$ExecutorPath=[IO.Path]::GetFullPath($ExecutorPath)
if(-not(Test-Path -LiteralPath $ExecutorPath -PathType Leaf)){throw 'Managed executor missing.'}
$policyPath=Join-Path (Split-Path -Parent $ExecutorPath) 'policy.json'
$policy=Get-Content -LiteralPath $policyPath -Encoding UTF8 -Raw|ConvertFrom-Json
if($MutexAssembly){
    $MutexAssembly=[IO.Path]::GetFullPath($MutexAssembly)
    if(-not(Test-Path -LiteralPath $MutexAssembly -PathType Leaf) -or (Get-Item -LiteralPath $MutexAssembly).Length -gt 4194304){throw 'Reviewed mutex assembly missing or oversized.'}
    $null=[Reflection.Assembly]::Load([IO.File]::ReadAllBytes($MutexAssembly))
}
$tag=[guid]::NewGuid().ToString('N')
$work=Join-Path ([IO.Path]::GetTempPath()) ('AgentExecMutexProbe-'+$tag)
if(Test-Path -LiteralPath $work){throw 'Fixture collision.'}
$security=[Security.AccessControl.DirectorySecurity]::new()
$security.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-18','S-1-5-32-544',$policy.storage_owner_sid)|Select-Object -Unique){
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
}
[IO.Directory]::CreateDirectory($work,$security)|Out-Null
$systemName='Global\AgentExec-MutexProbe-System-'+$tag
$userName='Global\AgentExec-MutexProbe-User-'+$tag
$taskName='AgentExecutionMutexProbe-'+$tag
$storeKeep=$null;$userMutex=$null;$registered=$false;$result=$null
try {
    # Keep the live store object's existing user-created handle alive, without
    # owning its lock. This isolates the probe from production-store ACL birth.
    $storeKeep=[Threading.Mutex]::new($false,'Global\AgentExec-RuntimeStore-v1')
    $userMutex=if($MutexAssembly){[AgentExecution.SharedMutex]::Open($userName,$policy.storage_owner_sid)}else{[Threading.Mutex]::new($false,$userName)}
    $body=@'
$ErrorActionPreference='Stop'
$work='__WORK__'
$assembly='__ASSEMBLY__'
$ownerSid='__OWNER__'
$system=$null;$user=$null
try {
    if($assembly){$null=[Reflection.Assembly]::Load([IO.File]::ReadAllBytes($assembly))}
    $system=if($assembly){[AgentExecution.SharedMutex]::Open('__SYSTEM__',$ownerSid)}else{[Threading.Mutex]::new($false,'__SYSTEM__')}
    $opened=$false;$openError=$null
    try{$user=if($assembly){[AgentExecution.SharedMutex]::Open('__USER__',$ownerSid)}else{[Threading.Mutex]::new($false,'__USER__')};$opened=$true}catch{$openError=$_.Exception.GetBaseException().GetType().Name}
    $row=[ordered]@{creator_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;system_opens_user=$opened;system_open_error=$openError;system_sddl=$system.GetAccessControl().GetSecurityDescriptorSddlForm('Access')}
    $json=$row|ConvertTo-Json -Compress
    if([Text.Encoding]::UTF8.GetByteCount($json)-gt 4096){throw 'Probe result exceeds bound.'}
    [IO.File]::WriteAllText((Join-Path $work 'ready.tmp'),$json,[Text.UTF8Encoding]::new($false))
    [IO.File]::Move((Join-Path $work 'ready.tmp'),(Join-Path $work 'ready.json'))
    $until=[DateTime]::UtcNow.AddSeconds(8)
    while(-not(Test-Path -LiteralPath (Join-Path $work 'ack')) -and [DateTime]::UtcNow -lt $until){Start-Sleep -Milliseconds 25}
}finally{if($user){$user.Dispose()};if($system){$system.Dispose()}}
'@
    $body=$body.Replace('__WORK__',$work.Replace("'","''")).Replace('__SYSTEM__',$systemName).Replace('__USER__',$userName).Replace('__ASSEMBLY__',([string]$MutexAssembly).Replace("'","''")).Replace('__OWNER__',[string]$policy.storage_owner_sid)
    $payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($body))
    $arguments='inline --owner background:goal2-mutex-system --shell powershell --timeout 15 --command-base64 '+$payload
    $action=New-ScheduledTaskAction -Execute $ExecutorPath -Argument $arguments
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([timespan]::FromSeconds(20)) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $definition=New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description ('Bounded GOAL2 principal probe '+$tag)
    Register-ScheduledTask -TaskName $taskName -TaskPath '\' -InputObject $definition|Out-Null
    $registered=$true
    Start-ScheduledTask -TaskName $taskName -TaskPath '\'
    $until=[DateTime]::UtcNow.AddSeconds(12)
    while(-not(Test-Path -LiteralPath (Join-Path $work 'ready.json')) -and [DateTime]::UtcNow -lt $until){Start-Sleep -Milliseconds 50}
    if(-not(Test-Path -LiteralPath (Join-Path $work 'ready.json'))){throw 'SYSTEM probe did not signal readiness; inspect task and owned run.'}
    $row=Get-Content -LiteralPath (Join-Path $work 'ready.json') -Encoding UTF8 -Raw|ConvertFrom-Json
    if($row.creator_sid -ne 'S-1-5-18'){throw 'Probe principal was not SYSTEM.'}
    $opened=$false;$openError=$null;$foreign=$null
    try{$foreign=if($MutexAssembly){[AgentExecution.SharedMutex]::Open($systemName,$policy.storage_owner_sid)}else{[Threading.Mutex]::new($false,$systemName)};$opened=$true}catch{$openError=$_.Exception.GetBaseException().GetType().Name}finally{if($foreign){$foreign.Dispose()}}
    [IO.File]::WriteAllBytes((Join-Path $work 'ack'),[byte[]]@())
    $until=[DateTime]::UtcNow.AddSeconds(8)
    do {
        $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\'
        $info=Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\'
        if([string]$task.State -eq 'Ready' -and $info.LastRunTime.Year -gt 2000){break}
        Start-Sleep -Milliseconds 50
    }while([DateTime]::UtcNow -lt $until)
    if([string]$task.State -ne 'Ready' -or $info.LastTaskResult -ne 0){throw 'SYSTEM managed probe did not finish successfully.'}
    if($MutexAssembly -and (-not $opened -or -not $row.system_opens_user)){throw 'Reviewed mutex helper does not support both principals.'}
    $result=[ordered]@{status='PASS';mode=$(if($MutexAssembly){'reviewed_helper'}else{'default_acl'});system_opens_user=$row.system_opens_user;system_open_error=$row.system_open_error;user_opens_system=$opened;user_open_error=$openError;system_sddl=$row.system_sddl.Replace([string]$policy.storage_owner_sid,'OPERATOR');task_result=$info.LastTaskResult;executor_job_deadline_seconds=15;task_deadline_seconds=20}
}finally{
    if($registered){
        $task=Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
        if($task -and [string]$task.State -eq 'Running'){
            Stop-ScheduledTask -TaskName $taskName -TaskPath '\'
            Start-Sleep -Milliseconds 100
        }
        if($task){Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false}
    }
    if($userMutex){$userMutex.Dispose()};if($storeKeep){$storeKeep.Dispose()}
    foreach($leaf in @('ack','ready.json','ready.tmp')){$p=Join-Path $work $leaf;if(Test-Path -LiteralPath $p){Remove-Item -LiteralPath $p}}
    if(Test-Path -LiteralPath $work){Remove-Item -LiteralPath $work}
}
$result|ConvertTo-Json -Compress
