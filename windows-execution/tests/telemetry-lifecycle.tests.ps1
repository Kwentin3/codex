param([string]$PolicyPath,[string]$RuntimeBinary,[switch]$NativeCounter,[switch]$NativeMaintenance)
$ErrorActionPreference='Stop'
$package=Split-Path -Parent $PSScriptRoot
. (Join-Path $package 'telemetry.ps1') -PolicyPath $PolicyPath
if($PolicyPath -and (Test-Path -LiteralPath $PolicyPath)){$policy=Get-TelemetryPolicy $PolicyPath}
else{
    $policy=Get-Content -LiteralPath (Join-Path $package 'policy.example.json') -Raw -Encoding UTF8|ConvertFrom-Json
    $policy.storage_owner_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}
$fixture=Join-Path $package ('telemetry-fixture-'+[guid]::NewGuid().ToString('N'))
$expected=[IO.Path]::GetFullPath($fixture)
$checks=[Collections.Generic.List[string]]::new()
$nativeEvidence=$null
$junction=$null
function Assert-That([bool]$Value,[string]$Message){if(-not $Value){throw "ASSERT: $Message"};$checks.Add($Message)}
try{
    if(Test-Path -LiteralPath $fixture){throw 'Fixture already exists'}
    [IO.Directory]::CreateDirectory($fixture)|Out-Null
    if(-not $RuntimeBinary -or -not(Test-Path -LiteralPath $RuntimeBinary -PathType Leaf)){throw 'Pass the compiled RuntimeBinary for the source under test.'}
    $module=Join-Path $fixture 'module';[IO.Directory]::CreateDirectory($module)|Out-Null
    $policy.execution.binary_name='agent-exec.v3.exe'
    Copy-Item -LiteralPath $RuntimeBinary -Destination (Join-Path $module $policy.execution.binary_name)
    $copied=Join-Path $module 'telemetry.ps1';Copy-Item -LiteralPath (Join-Path $package 'telemetry.ps1') -Destination $copied
    . $copied
    $policy.data_root=Join-Path $fixture 'data'
    # These rotation checks use real state/files/retention and a local fake PLA
    # lifecycle. They never install/start/stop a native data collector or task.
    $script:collector=[pscustomobject]@{Status=0}
    $script:stops=0
    $script:collector|Add-Member ScriptMethod Start {param($sync)$this.Status=1}
    $script:collector|Add-Member ScriptMethod Query {param($name,$server)}
    function Get-TelemetryCollector($Policy){return $script:collector}
    function Stop-TelemetryCollector($Policy){$script:stops++;$script:collector.Status=0}
    function Assert-TelemetryCollectorConfiguration($Policy,$Collector){}
    Initialize-TelemetryRoot $policy
    Start-TelemetryCollector $policy
    $statePath=Join-Path $policy.data_root 'active/current.json'
    $live=Join-Path $policy.data_root 'active/memory.blg'
    $started=[datetime]::UtcNow.AddHours(-1)
    [IO.File]::WriteAllText($statePath,(@{started_utc=$started.ToString('o')}|ConvertTo-Json -Compress))
    [IO.File]::WriteAllBytes($live,[byte[]]@(1,2))
    Invoke-TelemetryCommand $policy incident '' $null $null|Out-Null
    $pre=@(Get-TelemetryInventory $policy|Where-Object {$_.Bucket -eq 'incidents'})
    Assert-That ($pre.Count -eq 1 -and $pre[0].Bytes -eq 2) 'incident rotation retains pre-event segment as incident'
    Assert-That ([Math]::Abs(($pre[0].StartedUtc-$started).TotalMilliseconds) -lt 1) 'incident rotation preserves segment acquisition start'
    $postState=Get-Content -LiteralPath $statePath -Raw -Encoding UTF8|ConvertFrom-Json
    Assert-That ($postState.retention_class -eq 'incident') 'incident event marks next segment incident in native state'
    [IO.File]::WriteAllBytes($live,[byte[]]@(3,4,5))
    Move-TelemetryActive $policy $false
    $incidentRows=@(Get-TelemetryInventory $policy|Where-Object {$_.Bucket -eq 'incidents'})
    Assert-That ($incidentRows.Count -eq 2 -and @($incidentRows|Where-Object Bytes -eq 3).Count -eq 1) 'ordinary rotation retains post-event segment for incident age'
    Start-TelemetryCollector $policy
    Assert-That ((Get-Content -LiteralPath $statePath -Raw -Encoding UTF8|ConvertFrom-Json).retention_class -eq 'ordinary') 'following segment returns to ordinary retention'
    [IO.File]::WriteAllBytes($live,[byte[]]@(6))
    Move-TelemetryActive $policy $false
    Assert-That (@(Get-TelemetryInventory $policy|Where-Object {$_.Bucket -eq 'history'}).Count -eq 1) 'later ordinary segment uses existing history quota'
    Assert-That ((Get-TelemetryBytes @(Get-TelemetryInventory $policy) @('history','incidents')) -eq 6) 'incident and ordinary segments share original byte accounting'
    if($NativeMaintenance){
        Start-TelemetryCollector $policy
        $beforeStops=$script:stops
        $requests=Join-Path $policy.data_root 'runtime/requests';[IO.Directory]::CreateDirectory($requests)|Out-Null
        $known=Join-Path $requests ('a'*32+'.json');[IO.File]::WriteAllText($known,'malformed fixture JSON')
        $pf=Join-Path $fixture 'policy.json';[IO.File]::WriteAllText($pf,($policy|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
        $status=Invoke-TelemetryCommand $policy maintenance $pf $null $null
        Assert-That ($script:collector.Status -eq 1 -and $script:stops -eq $beforeStops) 'native semantic RunStore failure leaves healthy collector running'
        Assert-That ($status.gaps -contains 'RuntimeMaintenanceFailed' -and (Get-Item -LiteralPath (Join-Path $policy.data_root 'active/last-error.json')).Length -le 4096) 'runtime semantic failure remains visible in bounded private state'
        Assert-That ([IO.File]::ReadAllText($known) -eq 'malformed fixture JSON') 'telemetry never rewrites malformed runtime record'
        [IO.File]::Delete($known)
        $status=Invoke-TelemetryCommand $policy maintenance $pf $null $null
        Assert-That ($status.gaps -notcontains 'RuntimeMaintenanceFailed' -and $script:stops -eq $beforeStops) 'successful native recovery clears runtime warning without stopping collector'
        $temps=@(1..2|ForEach-Object {Join-Path $requests ('.tmp-'+[guid]::NewGuid().ToString('N')+'.tmp')})
        foreach($temp in $temps){[IO.File]::WriteAllText($temp,'owned orphan')}
        $status=Get-TelemetryStatus $policy
        Assert-That ($status.gaps -contains 'RuntimeRecoveryRequired' -and $status.runtime_storage.temp_files -eq 2) 'logical recovery conditions are visible without structural rejection'
        $status=Invoke-TelemetryCommand $policy maintenance $pf $null $null
        Assert-That (@($temps|Where-Object {Test-Path -LiteralPath $_}).Count -eq 0 -and $status.runtime_storage.logical_quota_valid -and $script:stops -eq $beforeStops) 'native owner alone recovers multiple temps while observation continues'
        $note=Join-Path $requests 'user-note.txt';[IO.File]::WriteAllText($note,'unowned fixture')
        $rejected=$false;try{Invoke-TelemetryCommand $policy maintenance $pf $null $null|Out-Null}catch{$rejected=$true}
        Assert-That ($rejected -and $script:stops -eq $beforeStops+1 -and [IO.File]::ReadAllText($note) -eq 'unowned fixture') 'unknown runtime namespace fails closed before semantic maintenance'
        [IO.File]::Delete($note);$script:collector.Status=1
        $bound=Join-Path $requests ('b'*32+'.ps1');[IO.File]::WriteAllBytes($bound,[byte[]]::new(65537))
        $rejected=$false;try{Invoke-TelemetryCommand $policy maintenance $pf $null $null|Out-Null}catch{$rejected=$true}
        Assert-That ($rejected -and $script:stops -eq $beforeStops+2) 'per-file runtime byte bound failure stops owned collector'
        [IO.File]::Delete($bound);$script:collector.Status=1
        $limit=$policy.retention.runtime_max_bytes;$policy.retention.runtime_max_bytes=2
        [IO.File]::WriteAllBytes($bound,[byte[]]@(1,2,3))
        $rejected=$false;try{Invoke-TelemetryCommand $policy maintenance $pf $null $null|Out-Null}catch{$rejected=$true}
        Assert-That ($rejected -and $script:stops -eq $beforeStops+3) 'aggregate runtime byte budget failure stops owned collector'
        [IO.File]::Delete($bound);$policy.retention.runtime_max_bytes=$limit;$script:collector.Status=1
        $target=Join-Path $fixture 'reparse-target';[IO.Directory]::CreateDirectory($target)|Out-Null
        $sentinel=Join-Path $target 'sentinel.txt';[IO.File]::WriteAllText($sentinel,'preserve')
        $junction=Join-Path $requests 'linked';New-Item -ItemType Junction -Path $junction -Target $target|Out-Null
        $rejected=$false;try{Invoke-TelemetryCommand $policy maintenance $pf $null $null|Out-Null}catch{$rejected=$true}
        Assert-That ($rejected -and $script:stops -eq $beforeStops+4 -and [IO.File]::ReadAllText($sentinel) -eq 'preserve') 'reparse runtime path fails closed and preserves target'
        [IO.Directory]::Delete($junction);$junction=$null
        [IO.File]::WriteAllText($note,'unowned uninstall fixture')
        $script:unregistered=[Collections.Generic.List[string]]::new();$script:deletedCollectors=0;$script:foreignTask=$false;$script:taskQueryFails=$false;$script:omitTasks=$false
        function Get-ScheduledTask {[CmdletBinding()]param($TaskPath,$TaskName)
            if($script:taskQueryFails){Write-Error 'Fixture task inventory unavailable' -Category PermissionDenied;return}
            if($script:omitTasks){return @()}
            foreach($name in Get-TelemetryTaskNames $policy){
                $description=if($script:foreignTask -and $name -like '*-Incident'){'foreign'}else{$script:TelemetryOwner}
                [pscustomobject]@{TaskName=$name.ToLowerInvariant();Description=$description}
            }
        }
        function Unregister-ScheduledTask {param($TaskName,$Confirm)$script:unregistered.Add($TaskName)}
        function Invoke-TelemetryLogman {param([string[]]$Arguments)if($Arguments[0] -ne 'delete'){throw 'Unexpected native action'};$script:deletedCollectors++}
        $beforeUninstall=@(Get-ChildItem -LiteralPath $policy.data_root -Recurse -File|ForEach-Object {($_.FullName+':'+(Get-FileHash -LiteralPath $_.FullName).Hash)}) -join '|'
        $receipt=Invoke-TelemetryCommand $policy uninstall $pf $null $null
        $afterUninstall=@(Get-ChildItem -LiteralPath $policy.data_root -Recurse -File|ForEach-Object {($_.FullName+':'+(Get-FileHash -LiteralPath $_.FullName).Hash)}) -join '|'
        Assert-That ($receipt.uninstalled -and $receipt.diagnostics_preserved -and $script:unregistered.Count -eq 2 -and $script:deletedCollectors -eq 1 -and $beforeUninstall -ceq $afterUninstall) 'uninstall bypasses broken runtime and preserves every diagnostic byte'
        $script:foreignTask=$true;$script:collector.Status=1;$beforeForeign=$script:stops
        $rejected=$false;try{Invoke-TelemetryCommand $policy uninstall $pf $null $null|Out-Null}catch{$rejected=$true}
        Assert-That ($rejected -and $script:stops -eq $beforeForeign -and $script:unregistered.Count -eq 2) 'uninstall validates all native task owners before any mutation'
        $script:foreignTask=$false;$script:taskQueryFails=$true
        $beforeQueryData=@(Get-ChildItem -LiteralPath $policy.data_root -Recurse -File|ForEach-Object {($_.FullName+':'+(Get-FileHash -LiteralPath $_.FullName).Hash)}) -join '|'
        $rejected=$false;try{Invoke-TelemetryCommand $policy uninstall $pf $null $null|Out-Null}catch{$rejected=$true}
        $afterQueryData=@(Get-ChildItem -LiteralPath $policy.data_root -Recurse -File|ForEach-Object {($_.FullName+':'+(Get-FileHash -LiteralPath $_.FullName).Hash)}) -join '|'
        Assert-That ($rejected -and $script:stops -eq $beforeForeign -and $script:unregistered.Count -eq 2 -and $script:deletedCollectors -eq 1 -and $beforeQueryData -ceq $afterQueryData) 'unavailable task inventory aborts with zero stops removals or data changes'
        $script:taskQueryFails=$false;$script:omitTasks=$true
        $receipt=Invoke-TelemetryCommand $policy uninstall $pf $null $null
        Assert-That ($receipt.uninstalled -and $script:unregistered.Count -eq 2) 'confirmed absence of configured tasks permits owned collector uninstall'
    }
    if($NativeCounter){
        # Native PLA renders the exact configured English paths without ever
        # committing a set; one read-only sample qualifies the additional path.
        $set=New-Object -ComObject Pla.DataCollectorSet
        $collectors=$set.DataCollectors;$counter=$collectors.CreateDataCollector(0)
        try{
            $counter.PerformanceCounters=$script:TelemetryCounters
            $display=@(([xml]$counter.Xml).PerformanceCounterDataCollector.CounterDisplayName)
            Assert-That ($display.Count -eq 8 -and $script:TelemetryCounters[-1] -ceq '\Process(*)\Handle Count') 'native PLA translates all eight configured counter paths'
            $sample=Get-Counter -Counter $display[-1] -MaxSamples 1 -ErrorAction Stop
            $valid=@($sample.CounterSamples|Where-Object {$_.Status -in @(0,1) -and $_.CookedValue -ge 0})
            Assert-That ($valid.Count -gt 0) 'native Handle Count provides valid nonnegative samples'
            $nativeEvidence=[pscustomobject]@{counter_paths=$display.Count;handle_samples=$sample.CounterSamples.Count;valid_handle_samples=$valid.Count;statuses=@($sample.CounterSamples.Status|Sort-Object -Unique);sample_utc=$sample.Timestamp.ToUniversalTime().ToString('o');interval_seconds=$policy.monitor.interval_seconds;native_max_mb=$policy.monitor.native_max_mb}
        }finally{
            foreach($com in @($counter,$collectors,$set)){if([Runtime.InteropServices.Marshal]::IsComObject($com)){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($com)}}
        }
    }
    [pscustomobject]@{result='PASS';assertions=$checks.Count;checks=$checks;native_counter=$nativeEvidence;native_maintenance_checked=[bool]$NativeMaintenance}|ConvertTo-Json -Depth 6 -Compress
}finally{
    if($junction -and (Test-Path -LiteralPath $junction)){[IO.Directory]::Delete($junction)}
    $resolved=[IO.Path]::GetFullPath($fixture)
    if($resolved -ne $expected -or (Split-Path $resolved -Parent) -ne [IO.Path]::GetFullPath($package).TrimEnd('\') -or (Split-Path $resolved -Leaf) -notmatch '^telemetry-fixture-[0-9a-f]{32}$'){throw 'Fixture cleanup containment failed'}
    if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
