param([string]$RuntimeBinary,[string]$NativeRunner,[string]$FixturePolicyPath)
$ErrorActionPreference='Stop'
$package=Split-Path -Parent $PSScriptRoot
$candidate=Join-Path $package 'telemetry.ps1'
. $candidate
$baselinePath=if($FixturePolicyPath){$FixturePolicyPath}else{Join-Path $package 'policy.example.json'}
$baseline=Get-Content -LiteralPath $baselinePath -Raw -Encoding UTF8|ConvertFrom-Json
$fixture=Join-Path $package ('AgentExecutionAccessTest-'+[guid]::NewGuid().ToString('N'))
$expected=[IO.Path]::GetFullPath($fixture)
$currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$baseline|Add-Member -NotePropertyName storage_owner_sid -NotePropertyValue $currentSid -Force
$checks=New-Object 'Collections.Generic.List[string]'
$script:stopCalls=0; $script:collectorCalls=0; $junction=$null
function Stop-TelemetryCollector($Policy){$script:stopCalls++;throw 'Unexpected native collector stop.'}
function Get-TelemetryCollector($Policy){$script:collectorCalls++;return $null}
function Assert-That([bool]$Value,[string]$Message){if(-not $Value){throw "ASSERT: $Message"};$checks.Add($Message)}
function Clone-Policy([string]$Name){$p=$baseline|ConvertTo-Json -Depth 8|ConvertFrom-Json;$p.data_root=Join-Path $fixture $Name;return $p}
function Save-Policy($Policy){[IO.File]::WriteAllText($policyFile,($Policy|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))}
function Assert-Rejected([scriptblock]$Action,[string]$Message){$bad=$false;try{& $Action|Out-Null}catch{$bad=$true};Assert-That $bad $Message}
function Public-DirectoryAcl {
    $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow));return $acl
}
try {
    if(Test-Path -LiteralPath $fixture){throw 'Fresh fixture root exists.'}
    [IO.Directory]::CreateDirectory($fixture)|Out-Null
    if(-not $RuntimeBinary -or -not(Test-Path -LiteralPath $RuntimeBinary -PathType Leaf)){throw 'Pass the compiled RuntimeBinary for the source under test.'}
    $module=Join-Path $fixture 'module';[IO.Directory]::CreateDirectory($module)|Out-Null
    $baseline.execution.binary_name='agent-exec.v3.exe'
    Copy-Item -LiteralPath $RuntimeBinary -Destination (Join-Path $module $baseline.execution.binary_name)
    $copied=Join-Path $module 'telemetry.ps1';Copy-Item -LiteralPath $candidate -Destination $copied
    $candidate=$copied;. $candidate
    function Stop-TelemetryCollector($Policy){$script:stopCalls++;throw 'Unexpected native collector stop.'}
    function Get-TelemetryCollector($Policy){$script:collectorCalls++;return $null}
    $nativeRunnerPath=if($NativeRunner){$NativeRunner}else{$RuntimeBinary}
    $policyFile=Join-Path $fixture 'policy.json'
    $p=Clone-Policy 'private';Save-Policy $p
    $loaded=Get-TelemetryPolicy $policyFile
    Assert-That ($loaded.storage_owner_sid -ceq $currentSid) 'native canonical policy owner SID retained'
    $bad=Clone-Policy 'bad';$bad.PSObject.Properties.Remove('storage_owner_sid');Save-Policy $bad
    Assert-Rejected {Get-TelemetryPolicy $policyFile} 'missing storage owner rejected'
    $bad|Add-Member -NotePropertyName storage_owner_sid -NotePropertyValue 'BUILTIN\Administrators';Save-Policy $bad
    Assert-Rejected {Get-TelemetryPolicy $policyFile} 'account display name rejected as SID'
    $bad.storage_owner_sid='S-invalid';Save-Policy $bad
    Assert-Rejected {Get-TelemetryPolicy $policyFile} 'invalid native SID rejected'
    $status=Get-TelemetryStatus $p
    Assert-That ($status.gaps -contains 'StorageRootMissing') 'missing storage root reported without creating it'
    Assert-That (-not(Test-Path -LiteralPath $p.data_root)) 'status remains read-only'
    $beforeCollector=$script:collectorCalls
    $init=Invoke-TelemetryCommand $p 'initialize-storage' $policyFile $null $null
    Assert-That ($init.storage_initialized -and $script:collectorCalls -eq $beforeCollector -and $script:stopCalls -eq 0) 'initialize-storage prepares private root without collector calls'
    foreach($path in @($p.data_root)+@('active','history','incidents','runtime'|ForEach-Object {Join-Path $p.data_root $_})){
        Assert-That (Test-TelemetryStorageAccess $p $path $true) 'root and four buckets have protected inheritable private ACL'
    }
    $requests=Join-Path $p.data_root 'runtime/requests'
    [IO.Directory]::CreateDirectory($requests)|Out-Null
    $scriptFile=Join-Path $requests (([guid]::NewGuid().ToString('N'))+'.ps1')
    [IO.File]::WriteAllText($scriptFile,'ordinary workload')
    Assert-That (Test-TelemetryStorageAccess $p $requests) 'plain future runtime directory inherits only policy principals at birth'
    Assert-That (Test-TelemetryStorageAccess $p $scriptFile) 'plain future workload file inherits private ACL at birth'
    Assert-That ((Get-TelemetryStatus $p).gaps -notcontains 'StorageAclDrift') 'private storage reports no ACL drift'
    # Native runner parity is checked outside Store gate: public Status owns
    # state/content interpretation; our consumer only admits its namespace.
    Save-Policy $p
    $savedPreference=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $nativeResult=& $nativeRunnerPath status --policy $policyFile 2>&1
        $nativeOk=$LASTEXITCODE
    } finally {$ErrorActionPreference=$savedPreference}
    Assert-That ($nativeOk -eq 0) 'selected native runner accepts owned fixture namespace'
    $note=Join-Path $requests 'user-note.txt';[IO.File]::WriteAllText($note,'unowned preserve')
    $noteAcl=(Get-Acl -LiteralPath $note).Sddl;$noteHash=(Get-FileHash -LiteralPath $note).Hash
    Assert-Rejected {Initialize-TelemetryRoot $p} 'unknown runtime leaf rejected before ACL mutation'
    Assert-That ((Get-Acl -LiteralPath $note).Sddl -ceq $noteAcl -and (Get-FileHash -LiteralPath $note).Hash -ceq $noteHash) 'unknown runtime leaf ACL and bytes preserved'
    try {
        $ErrorActionPreference='Continue'
        $nativeResult=& $nativeRunnerPath status --policy $policyFile 2>&1
        $nativeRejected=$LASTEXITCODE
    } finally {$ErrorActionPreference=$savedPreference}
    Assert-That ($nativeRejected -ne 0) 'selected native runner rejects same unknown runtime leaf'
    [IO.File]::Delete($note)
    # A second runspace attempts the real removal at each snapshot/ACL seam.
    # It may mutate only while holding the deployed Store mutex. Without the
    # caller gate this deterministically deletes the snapshotted workload file.
    $request=[Threading.ManualResetEventSlim]::new($false);$done=[Threading.ManualResetEventSlim]::new($false)
    $observed=[Collections.Concurrent.ConcurrentQueue[bool]]::new()
    $worker=[PowerShell]::Create();$async=$null;$accessOwner=${function:Test-TelemetryStorageAccess};$script:lockProbes=0
    $churnFile=Join-Path $requests ('e'*32+'.ps1')
    $null=$worker.AddScript({param($request,$done,$observed,$victim,$churnFile)
        $gate=[Threading.Mutex]::new($false,'Global\AgentExec-RuntimeStore-v1')
        try {
            for($i=0;$i -lt 2;$i++){
                if(-not $request.Wait(5000)){throw 'Snapshot probe handshake timeout'};$request.Reset()
                $held=$gate.WaitOne(0);$observed.Enqueue($held)
                try{if($held){[IO.File]::Delete($victim)}}finally{if($held){$gate.ReleaseMutex()}};$done.Set()
            }
            for($i=0;$i -lt 30;$i++){
                if(-not $gate.WaitOne(5000)){throw 'Churn store timeout'}
                try{[IO.File]::WriteAllText($churnFile,'owned churn');[Threading.Thread]::Sleep(2);[IO.File]::Delete($churnFile)}finally{$gate.ReleaseMutex()}
                [Threading.Thread]::Sleep(1)
            }
            return 30
        }finally{$gate.Dispose()}
    }).AddArgument($request).AddArgument($done).AddArgument($observed).AddArgument($scriptFile).AddArgument($churnFile)
    function Test-TelemetryStorageAccess($Policy,[string]$Path,[bool]$ProtectedDirectory=$false){
        if($Path -eq $scriptFile -and $script:lockProbes -lt 2){$script:lockProbes++;$done.Reset();$request.Set();if(-not $done.Wait(5000)){throw 'ACL snapshot probe timeout'}}
        return (& $accessOwner $Policy $Path $ProtectedDirectory)
    }
    try {
        $async=$worker.BeginInvoke()
        Initialize-TelemetryRoot $p;Get-TelemetryStatus $p|Out-Null
        for($i=0;$i -lt 5;$i++){Initialize-TelemetryRoot $p;Get-TelemetryStatus $p|Out-Null}
        $cycles=@($worker.EndInvoke($async))
        if($worker.Streams.Error.Count){throw ($worker.Streams.Error|Out-String)}
        Assert-That ($observed.Count -eq 2 -and @($observed.ToArray()|Where-Object {$_}).Count -eq 0) 'initialization and status retain Store mutex through snapshot and ACL reads'
        Assert-That ($cycles[0] -eq 30 -and (Test-Path -LiteralPath $scriptFile)) 'runtime churn shares Store mutex without disappearing snapshot files'
    } finally {
        Set-Item -Path function:Test-TelemetryStorageAccess -Value $accessOwner
        if($async -and -not $async.IsCompleted){$worker.Stop()};$worker.Dispose();$request.Dispose();$done.Dispose()
    }
    $existing=Clone-Policy 'existing'
    [IO.Directory]::CreateDirectory((Join-Path $existing.data_root 'active'))|Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $existing.data_root 'incidents'))|Out-Null
    [IO.Directory]::SetAccessControl($existing.data_root,(Public-DirectoryAcl))
    $public=Join-Path $existing.data_root 'active/current.json';[IO.File]::WriteAllText($public,'{}')
    $protected=Join-Path $existing.data_root ('incidents/ae-'+[datetime]::UtcNow.ToString("yyyyMMdd'T'HHmmssfff'Z'")+'-12345678.zip')
    [IO.File]::WriteAllBytes($protected,[byte[]]@(1,2,3))
    [IO.File]::SetAccessControl($protected,(New-TelemetryStorageSecurity $existing $false))
    $privateBefore=(Get-Acl -LiteralPath $protected).Sddl
    Assert-That ((Get-TelemetryStatus $existing).gaps -contains 'StorageAclDrift') 'public existing root is reported as ACL drift'
    Initialize-TelemetryRoot $existing
    Assert-That (Test-TelemetryStorageAccess $existing $public) 'existing publicly inherited payload sealed'
    Assert-That ((Get-Acl -LiteralPath $protected).Sddl -ceq $privateBefore) 'already-private protected archive ACL remains unchanged'
    Assert-That ([Convert]::ToBase64String([IO.File]::ReadAllBytes($protected)) -eq 'AQID') 'existing archive bytes unchanged'
    $unsafe=Clone-Policy 'unsafe';[IO.Directory]::CreateDirectory($unsafe.data_root)|Out-Null
    [IO.Directory]::SetAccessControl($unsafe.data_root,(Public-DirectoryAcl))
    $unknown=Join-Path $unsafe.data_root 'unknown.txt';[IO.File]::WriteAllText($unknown,'preserve')
    $unsafeBefore=(Get-Acl -LiteralPath $unsafe.data_root).Sddl
    Assert-Rejected {Initialize-TelemetryRoot $unsafe} 'unknown existing namespace rejected before ACL mutation'
    Assert-That ((Get-Acl -LiteralPath $unsafe.data_root).Sddl -ceq $unsafeBefore) 'unsafe existing root ACL preserved on rejection'
    $linked=Clone-Policy 'linked';[IO.Directory]::CreateDirectory($linked.data_root)|Out-Null
    $junction=Join-Path $linked.data_root 'runtime'
    New-Item -ItemType Junction -Path $junction -Target $p.data_root|Out-Null
    Assert-Rejected {Initialize-TelemetryRoot $linked} 'reparse existing namespace rejected before ACL mutation'
    $cross=Clone-Policy 'cross';$cross.storage_owner_sid=$currentSid.Substring(0,$currentSid.LastIndexOf('-')+1)+'501'
    Initialize-TelemetryRoot $cross
    $rules=(Get-Acl -LiteralPath $cross.data_root).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    Assert-That (@($rules|Where-Object {$_.IdentityReference.Value -eq $cross.storage_owner_sid}).Count -eq 1) 'policy operator SID retained when creator principal differs'
    Assert-That (@($rules|Where-Object {$_.IdentityReference.Value -eq $currentSid}).Count -eq 0) 'creator identity does not replace explicit policy operator SID'
    Assert-That (@($rules|Where-Object {$_.IdentityReference.Value -eq 'S-1-5-18'}).Count -eq 1) 'SYSTEM access retained alongside policy operator'
    $edge=Clone-Policy 'receipt-edge';Initialize-TelemetryRoot $edge
    $edgeReceipts=Join-Path $edge.data_root 'runtime/receipts';[IO.Directory]::CreateDirectory($edgeReceipts)|Out-Null
    for($i=0;$i -lt 8;$i++){
        $name=[datetime]::UtcNow.AddSeconds(-60-$i).ToString("yyyyMMdd'T'HHmmssfffffff'Z'")+'-'+[guid]::NewGuid().ToString('N')+'.jsonl'
        [IO.File]::WriteAllText((Join-Path $edgeReceipts $name),"{}`n")
    }
    $orphan=Join-Path $edgeReceipts ('.tmp-'+[guid]::NewGuid().ToString('N')+'.tmp');[IO.File]::WriteAllText($orphan,'orphan')
    Initialize-TelemetryRoot $edge
    Assert-That ((Test-Path -LiteralPath $orphan) -and @(Get-ChildItem -LiteralPath $edgeReceipts -File).Count -eq 9) 'eight receipts plus one orphan temp admitted without consuming native recovery state'
    Save-Policy $edge
    try {
        $ErrorActionPreference='Continue'
        $nativeResult=& $nativeRunnerPath status --policy $policyFile 2>&1
        $nativeEdge=$LASTEXITCODE
    } finally {$ErrorActionPreference=$savedPreference}
    Assert-That ($nativeEdge -eq 0 -and -not(Test-Path -LiteralPath $orphan) -and @(Get-ChildItem -LiteralPath $edgeReceipts -File).Count -eq 8) 'selected native runner accepts same eight-plus-temp edge and performs orphan cleanup'
    Assert-That ($script:stopCalls -eq 0) 'privacy checks never touch native collector'
    # Reuse every accepted archive assertion against this candidate and a
    # fieldful isolated policy; the existing test still defaults to live source.
    Save-Policy $cross
    & (Join-Path $PSScriptRoot 'evidence-archive.tests.ps1') -TelemetryPath $candidate -PolicyPath $policyFile
    [pscustomobject]@{result='PASS';privacy_assertions=$checks.Count;checks=$checks}|ConvertTo-Json -Depth 4 -Compress
} finally {
    if($junction -and (Test-Path -LiteralPath $junction)){[IO.Directory]::Delete($junction)}
    $resolved=[IO.Path]::GetFullPath($fixture)
    if($resolved -ne $expected -or (Split-Path $resolved -Leaf) -notmatch '^AgentExecutionAccessTest-[0-9a-f]{32}$' -or (Split-Path $resolved -Parent) -ne [IO.Path]::GetFullPath($package).TrimEnd('\')){throw 'Fixture cleanup containment failed.'}
    if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
