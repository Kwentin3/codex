[CmdletBinding()]
param(
    [ValidateSet('maintenance','status','initialize-storage','incident','import-artifact','archive-evidence','install','uninstall')]
    [string]$Command = 'status',
    [string]$PolicyPath,
    [string]$SourceDirectory,
    [string]$ArtifactPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:TelemetryScriptPath = $MyInvocation.MyCommand.Path
if (-not $PolicyPath) { $PolicyPath = Join-Path (Split-Path -Parent $script:TelemetryScriptPath) 'policy.json' }
$script:TelemetryOwner = 'AgentExecution telemetry schema1'
$script:TelemetryCounters = @(
    '\Memory\Committed Bytes', '\Memory\Commit Limit', '\Memory\Available MBytes',
    '\Memory\Pool Paged Bytes', '\Memory\Pool Nonpaged Bytes',
    '\Process(*)\ID Process', '\Process(*)\Private Bytes'
)

function Get-TelemetryPolicy([string]$Path) {
    $p = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($p.schema_version -ne 1) { throw 'Unsupported telemetry policy schema.' }
    if ($p.PSObject.Properties.Name -notcontains 'storage_owner_sid' -or $p.storage_owner_sid -isnot [string]) { throw 'Explicit storage_owner_sid required.' }
    try { $ownerSid = [Security.Principal.SecurityIdentifier]::new($p.storage_owner_sid) }
    catch { throw 'Invalid native storage_owner_sid.' }
    if ($ownerSid.Value -cne $p.storage_owner_sid) { throw 'storage_owner_sid must be a canonical native SID string.' }
    $p.data_root = [IO.Path]::GetFullPath($p.data_root).TrimEnd('\')
    if ($p.data_root -eq [IO.Path]::GetPathRoot($p.data_root).TrimEnd('\')) { throw 'A volume root cannot own diagnostics.' }
    $r = $p.retention
    foreach ($key in @('ordinary_days','incident_days','total_bytes','active_reserved_bytes','closed_max_bytes','runtime_max_bytes','margin_bytes')) {
        if ([long]$r.$key -le 0) { throw "Invalid retention value: $key" }
    }
    if ([long]$r.active_reserved_bytes + [long]$r.closed_max_bytes + [long]$r.runtime_max_bytes + [long]$r.margin_bytes -gt [long]$r.total_bytes) { throw 'Budget partitions exceed total_bytes.' }
    if ($p.monitor.collector_name -notmatch '^AgentExecution[A-Za-z0-9-]*$') { throw 'Collector name must be task-owned AgentExecution*.' }
    if ([int]$p.monitor.native_max_mb -le 0 -or ([long]$p.monitor.native_max_mb * 1MB) -ge [long]$r.active_reserved_bytes) { throw 'Native BLG needs headroom inside active reservation.' }
    if ([int]$p.monitor.interval_seconds -lt 1 -or [double]$p.monitor.period_hours -le 0) { throw 'Invalid collector interval/duration.' }
    return $p
}

function Assert-TelemetryPath([string]$Path, [string]$Root) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $base = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if ($full -ne $base -and -not $full.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Path outside diagnostics scope: $full" }
    $cursor = $full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point refused: $cursor" }
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $full
}

function New-TelemetryStorageSecurity($Policy,[bool]$Directory) {
    $security = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $security.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544',$Policy.storage_owner_sid) | Select-Object -Unique) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        if ($Directory) {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
        } else {
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
        }
    }
    return $security
}

function Test-TelemetryStorageAccess($Policy,[string]$Path,[bool]$ProtectedDirectory=$false) {
    $acl = Get-Acl -LiteralPath $Path
    if ($ProtectedDirectory -and -not $acl.AreAccessRulesProtected) { return $false }
    $allowed = @('S-1-5-18','S-1-5-32-544',$Policy.storage_owner_sid) | Select-Object -Unique
    $found = @{}
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin $allowed) { return $false }
        if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl) {
            if (-not $ProtectedDirectory -or ($rule.InheritanceFlags -band ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit)) -eq ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit)) { $found[$rule.IdentityReference.Value]=$true }
        }
    }
    return (@($allowed|Where-Object {-not $found.ContainsKey($_)}).Count -eq 0)
}

function Invoke-TelemetryStoreSnapshot([scriptblock]$Action) {
    # Same installed mutex as pinned source-v1/RunStore.cs. Caller order is
    # telemetry -> store; never keep this gate across child runner/COM calls.
    $gate=[Threading.Mutex]::new($false,'Global\AgentExec-RuntimeStore-v1'); $held=$false
    try {
        try { $held=$gate.WaitOne([timespan]::FromSeconds(10)) } catch [Threading.AbandonedMutexException] { $held=$true }
        if (-not $held) { throw 'Runtime store is busy; no storage snapshot or ACL mutation.' }
        return (& $Action)
    } finally { if ($held) { $gate.ReleaseMutex() }; $gate.Dispose() }
}

function Assert-TelemetryRuntimeLeaves($Policy,[string]$Runtime) {
    # Consumer validation of deployed v1 Inspect/IsTemp/ReceiptDate only.
    # RunStore remains the owner of record contents and state transitions.
    $temps=0; $active=0; $receipts=0; $bytes=[long]0
    $pending=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($dir in Get-ChildItem -LiteralPath $Runtime -Force) {
        if (-not $dir.PSIsContainer -or $dir.Name -cnotin @('requests','active','receipts')) { throw 'Unknown runtime storage namespace; ACL preserved.' }
        foreach ($file in Get-ChildItem -LiteralPath $dir.FullName -Force) {
            Assert-TelemetryPath $file.FullName $Runtime | Out-Null
            if ($file.PSIsContainer) { throw 'Unknown nested runtime storage directory; ACL preserved.' }
            $temp=$file.Name -cmatch '^\.tmp-[0-9a-fA-F]{32}\.tmp$'
            $maximum=524288
            if ($temp) { $temps++ }
            elseif ($dir.Name -eq 'receipts') {
                if ($file.Name -cnotmatch '^(\d{8}T\d{13}Z)-[0-9a-fA-F]{32}\.jsonl$') { throw 'Unknown v1 receipt file; ACL preserved.' }
                $date=[datetime]::ParseExact($Matches[1],"yyyyMMdd'T'HHmmssfffffff'Z'",[Globalization.CultureInfo]::InvariantCulture,([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal))
                if ($date -gt [datetime]::UtcNow.AddMinutes(5)) { throw 'Future v1 receipt filename; ACL preserved.' }
            } else {
                if ($file.BaseName -cnotmatch '^[0-9a-f]{32}$') { throw 'Unknown v1 runtime file; ACL preserved.' }
                if ($dir.Name -eq 'requests') {
                    if ($file.Extension -cin @('.json','.ps1')) { $maximum=65536 }
                    elseif ($file.Extension -ceq '.claimed') { $maximum=1024 }
                    else { throw 'Unknown v1 request extension; ACL preserved.' }
                    $null=$pending.Add($file.BaseName)
                } else {
                    if ($file.Extension -ceq '.json') { $maximum=4096 }
                    elseif ($file.Extension -ceq '.cancel') { $maximum=0 }
                    else { throw 'Unknown v1 active extension; ACL preserved.' }
                    $active++
                }
            }
            if ($dir.Name -eq 'receipts' -and -not $temp) { $receipts++ }
            if ($file.Length -gt $maximum) { throw 'V1 runtime file quota violated; ACL preserved.' }
            $bytes += [long]$file.Length
        }
    }
    if ($temps -gt 1 -or $pending.Count -gt 32 -or $active -gt 32 -or $receipts -gt 8 -or $bytes -gt $Policy.retention.runtime_max_bytes) { throw 'V1 runtime quota violated; ACL preserved.' }
}

function Get-TelemetryStoragePaths($Policy) {
    $root = Assert-TelemetryPath $Policy.data_root $Policy.data_root
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    # Validate the whole owned namespace before changing any existing ACL.
    $rows = @(Get-TelemetryInventory $Policy)
    $paths = @([pscustomobject]@{Path=$root;Directory=$true;Protected=$true})
    foreach ($name in @('active','history','incidents','runtime')) {
        $path = Join-Path $root $name
        if (Test-Path -LiteralPath $path) { $paths += [pscustomobject]@{Path=$path;Directory=$true;Protected=$true} }
    }
    $runtime = Join-Path $root 'runtime'
    if (Test-Path -LiteralPath $runtime) {
        Assert-TelemetryRuntimeLeaves $Policy $runtime
        foreach ($child in Get-ChildItem -LiteralPath $runtime -Force) {
            if (-not $child.PSIsContainer -or $child.Name -notin @('requests','active','receipts')) { throw 'Unknown runtime storage namespace; ACL preserved.' }
            if (@(Get-ChildItem -LiteralPath $child.FullName -Directory -Force).Count) { throw 'Unknown nested runtime storage directory; ACL preserved.' }
            $paths += [pscustomobject]@{Path=$child.FullName;Directory=$true;Protected=$false}
        }
    }
    foreach ($row in $rows) { $paths += [pscustomobject]@{Path=$row.Path;Directory=$false;Protected=$false} }
    return $paths
}

function Initialize-TelemetryRoot($Policy) {
    Invoke-TelemetryStoreSnapshot {
    $root = Assert-TelemetryPath $Policy.data_root $Policy.data_root
    $known = @(Get-TelemetryStoragePaths $Policy)
    $privateDirectory = New-TelemetryStorageSecurity $Policy $true
    [IO.Directory]::CreateDirectory($root,$privateDirectory) | Out-Null
    [IO.Directory]::SetAccessControl($root,$privateDirectory)
    foreach ($name in @('active','history','incidents','runtime')) {
        $path = Assert-TelemetryPath (Join-Path $root $name) $root
        [IO.Directory]::CreateDirectory($path,$privateDirectory) | Out-Null
        [IO.Directory]::SetAccessControl($path,$privateDirectory)
    }
    foreach ($item in $known) {
        Assert-TelemetryPath $item.Path $root | Out-Null
        if (-not (Test-TelemetryStorageAccess $Policy $item.Path $item.Protected)) {
            $security = New-TelemetryStorageSecurity $Policy $item.Directory
            if ($item.Directory) { [IO.Directory]::SetAccessControl($item.Path,$security) }
            else { [IO.File]::SetAccessControl($item.Path,$security) }
        }
    }
    }
}

function Get-TelemetryInventory($Policy) {
    $root = Assert-TelemetryPath $Policy.data_root $Policy.data_root
    $rows = @()
    if (Test-Path -LiteralPath $root) {
        foreach ($entry in Get-ChildItem -LiteralPath $root -Force) {
            if (-not $entry.PSIsContainer -or $entry.Name -notin @('active','history','incidents','runtime')) { throw "Unknown diagnostics root entry: $($entry.Name)" }
        }
        foreach ($bucket in @('active','history','incidents','runtime')) {
            $dir = Join-Path $root $bucket
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            Assert-TelemetryPath $dir $root | Out-Null
            # Traverse one level at a time; never follow a reparse point before validating it.
            $pending = New-Object 'Collections.Generic.Queue[string]'
            $pending.Enqueue($dir)
            while ($pending.Count) {
                foreach ($file in Get-ChildItem -LiteralPath $pending.Dequeue() -Force) {
                    Assert-TelemetryPath $file.FullName $root | Out-Null
                    if ($file.PSIsContainer) {
                        if ($bucket -ne 'runtime') { throw "Unknown telemetry subdirectory: $($file.FullName)" }
                        $pending.Enqueue($file.FullName)
                        continue
                    }
                    $started = $null
                    if ($bucket -eq 'active' -and $file.Name -notin @('memory.blg','current.json','last-error.json')) { throw "Unknown active telemetry file: $($file.Name)" }
                    if ($bucket -eq 'active' -and $file.Extension -eq '.json' -and $file.Length -gt 4096) { throw 'Active state file exceeds its bound.' }
                    if ($bucket -in @('history','incidents')) {
                        if ($file.Name -notmatch '^ae-(\d{8}T\d{9}Z)-[0-9a-f]{8}\.(blg|json|txt|log|xml|csv|zip)$') { throw "Unknown retained telemetry file: $($file.Name)" }
                        $started = [datetime]::ParseExact($Matches[1], "yyyyMMdd'T'HHmmssfff'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal).ToUniversalTime()
                    }
                    $rows += [pscustomobject]@{ Path=$file.FullName; Bucket=$bucket; Bytes=[long]$file.Length; StartedUtc=$started }
                }
            }
        }
    }
    return $rows
}

function Get-TelemetryBytes($Rows, [string[]]$Buckets) {
    $sum = [long]0
    foreach ($row in $Rows) { if ($row.Bucket -in $Buckets) { $sum += $row.Bytes } }
    return $sum
}

function Remove-TelemetryFile($Policy, $Row) {
    Assert-TelemetryPath $Row.Path $Policy.data_root | Out-Null
    Remove-Item -LiteralPath $Row.Path -Force
    if (Test-Path -LiteralPath $Row.Path) { throw 'Artifact deletion did not complete.' }
}

function Invoke-TelemetryPrune($Policy, [long]$IncomingBytes = 0) {
    if ($IncomingBytes -lt 0 -or $IncomingBytes -gt [long]$Policy.retention.closed_max_bytes) { throw 'Artifact exceeds closed-data budget.' }
    $rows = @(Get-TelemetryInventory $Policy)
    foreach ($row in $rows | Where-Object { $_.Bucket -in @('history','incidents') }) {
        $days = if ($row.Bucket -eq 'history') { $Policy.retention.ordinary_days } else { $Policy.retention.incident_days }
        # Early expiry covers the regular 15-minute scheduling interval.
        if ($row.StartedUtc -le [datetime]::UtcNow.AddDays(-[double]$days).AddMinutes(15)) { Remove-TelemetryFile $Policy $row }
    }
    $rows = @(Get-TelemetryInventory $Policy)
    if ((Get-TelemetryBytes $rows @('runtime')) -gt [long]$Policy.retention.runtime_max_bytes) { throw 'Runtime partition exceeds its reservation.' }
    if ((Get-TelemetryBytes $rows @('active')) -gt [long]$Policy.retention.active_reserved_bytes) { throw 'Native active partition exceeds its reservation.' }
    $cold = Get-TelemetryBytes $rows @('history','incidents')
    foreach ($row in $rows | Where-Object { $_.Bucket -in @('history','incidents') } | Sort-Object @{Expression={ if ($_.Bucket -eq 'history') { 0 } else { 1 } }},StartedUtc,Path) {
        if ($cold + $IncomingBytes -le [long]$Policy.retention.closed_max_bytes) { break }
        Remove-TelemetryFile $Policy $row
        $cold -= $row.Bytes
    }
    if ($cold + $IncomingBytes -gt [long]$Policy.retention.closed_max_bytes) { throw 'Cannot admit closed artifact.' }
    if ($cold + $IncomingBytes + [long]$Policy.retention.active_reserved_bytes + [long]$Policy.retention.runtime_max_bytes + [long]$Policy.retention.margin_bytes -gt [long]$Policy.retention.total_bytes) { throw 'Aggregate admission exceeds hard budget.' }
}

function Get-TelemetryCollector($Policy) {
    $dcs = New-Object -ComObject Pla.DataCollectorSet
    try { $dcs.Query($Policy.monitor.collector_name, $null) }
    catch {
        if ($_.Exception.HResult -in @(-2144337918,-2147024894)) { return $null }
        # PLA reports missing sets with different wrappers on supported Windows builds.
        if ($_.Exception.Message -match '0x80300002|0x80070002') { return $null }
        throw
    }
    $active = Join-Path $Policy.data_root 'active'
    if ($dcs.Description -ne $script:TelemetryOwner -or [IO.Path]::GetFullPath($dcs.RootPath).TrimEnd('\') -ne $active) { throw 'Refusing foreign collector with our configured name.' }
    return $dcs
}

function Stop-TelemetryCollector($Policy) {
    $dcs = Get-TelemetryCollector $Policy
    if ($null -ne $dcs -and $dcs.Status -ne 0) {
        $dcs.Stop($true)
        $dcs.Query($Policy.monitor.collector_name, $null)
        if ($dcs.Status -ne 0) { throw 'Own collector did not stop; no rotation allowed.' }
    }
}

function Invoke-TelemetryLogman([string[]]$Arguments) {
    $lines = @(& "$env:SystemRoot\System32\logman.exe" @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw ('logman failed: ' + (($lines -join ' ') | Select-Object -First 1)) }
}

function New-TelemetryCollector($Policy) {
    $existing = Get-TelemetryCollector $Policy
    if ($null -ne $existing) { Assert-TelemetryCollectorConfiguration $Policy $existing; return }
    $seconds = [int]([double]$Policy.monitor.period_hours * 3600)
    $duration = '{0:00}:{1:00}:{2:00}' -f [math]::Floor($seconds/3600),([math]::Floor($seconds/60)%60),($seconds%60)
    $interval = [timespan]::FromSeconds([int]$Policy.monitor.interval_seconds).ToString('hh\:mm\:ss')
    $args = @('create','counter',$Policy.monitor.collector_name,'-c') + $script:TelemetryCounters + @('-f','bincirc','-max',[string]$Policy.monitor.native_max_mb,'-si',$interval,'-rf',$duration,'-o',(Join-Path $Policy.data_root 'active\memory.blg'),'-ow','--v')
    Invoke-TelemetryLogman $args
    $dcs = New-Object -ComObject Pla.DataCollectorSet
    $dcs.Query($Policy.monitor.collector_name,$null)
    $dcs.Description = $script:TelemetryOwner
    $dcs.Commit($Policy.monitor.collector_name,$null,0) | Out-Null
}

function Assert-TelemetryCollectorConfiguration($Policy, $Collector) {
    if ($Collector.DataCollectors.Count -ne 1) { throw 'Owned collector configuration drift: unexpected data collectors.' }
    $counter = $Collector.DataCollectors.Item(0)
    # PLA exposes counter display paths in the querying principal's native language.
    # Let the same native owner render our English definition before exact comparison.
    $nativeSet = New-Object -ComObject Pla.DataCollectorSet
    $nativeCounter = $nativeSet.DataCollectors.CreateDataCollector(0)
    $nativeCounter.PerformanceCounters = $script:TelemetryCounters
    $expectedCounters = @(([xml]$nativeCounter.Xml).PerformanceCounterDataCollector.CounterDisplayName)
    if ($expectedCounters.Count -ne $script:TelemetryCounters.Count -or @($expectedCounters | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count) { throw 'Native counter display translation is incomplete.' }
    $expected = [ordered]@{
        counters=(@($expectedCounters | Sort-Object) -join '|'); circular=$true; append=$false; overwrite=$true
        file_name_format=0; file_name='memory'; log_format=3; interval_seconds=[int]$Policy.monitor.interval_seconds
        segment=$false; max_mb=[int]$Policy.monitor.native_max_mb; duration_seconds=[int]([double]$Policy.monitor.period_hours*3600)
    }
    $actual = [ordered]@{
        counters=(@($counter.PerformanceCounters | Sort-Object) -join '|'); circular=[bool]$counter.LogCircular; append=[bool]$counter.LogAppend; overwrite=[bool]$counter.LogOverwrite
        file_name_format=[int]$counter.FileNameFormat; file_name=[string]$counter.FileName; log_format=[int]$counter.LogFileFormat; interval_seconds=[int]$counter.SampleInterval
        segment=[bool]$Collector.Segment; max_mb=[int]$Collector.SegmentMaxSize; duration_seconds=[int]$Collector.Duration
    }
    foreach ($field in $expected.Keys) {
        if ($actual[$field] -ne $expected[$field]) {
            $detail = [ordered]@{ field=$field; expected=$expected[$field]; actual=$actual[$field]; culture=[Globalization.CultureInfo]::CurrentCulture.Name; ui_culture=[Globalization.CultureInfo]::CurrentUICulture.Name } | ConvertTo-Json -Compress
            throw ('Owned collector configuration drift: '+$detail)
        }
    }
}

function Write-TelemetryState($Policy) {
    $state = @{ started_utc=[datetime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress
    $path = Join-Path $Policy.data_root 'active\current.json'
    if ([Text.Encoding]::UTF8.GetByteCount($state) -gt 1024) { throw 'Active state exceeds bound.' }
    [IO.File]::WriteAllText($path,$state,[Text.UTF8Encoding]::new($false))
}

function Start-TelemetryCollector($Policy) {
    Invoke-TelemetryPrune $Policy
    $dcs = Get-TelemetryCollector $Policy
    if ($null -eq $dcs) { throw 'Collector is not installed.' }
    Assert-TelemetryCollectorConfiguration $Policy $dcs
    if ($dcs.Status -eq 1) { return }
    if ($dcs.Status -ne 0) { throw 'Collector is transitioning; do not duplicate it.' }
    Write-TelemetryState $Policy
    $dcs.Start($true)
    $dcs.Query($Policy.monitor.collector_name,$null)
    if ($dcs.Status -ne 1) { throw 'Own collector did not enter Running.' }
    $errorPath = Join-Path $Policy.data_root 'active\last-error.json'
    if (Test-Path -LiteralPath $errorPath) { Remove-Item -LiteralPath $errorPath -Force }
}

function Move-TelemetryActive($Policy, [bool]$Incident) {
    Stop-TelemetryCollector $Policy
    $live = Join-Path $Policy.data_root 'active\memory.blg'
    $statePath = Join-Path $Policy.data_root 'active\current.json'
    if (Test-Path -LiteralPath $live) {
        if (-not (Test-Path -LiteralPath $statePath)) { throw 'Active BLG has no earliest-data state; refusing to guess retention age.' }
        $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $started = [datetime]::Parse($state.started_utc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        $file = Get-Item -LiteralPath $live
        Invoke-TelemetryPrune $Policy $file.Length
        $bucket = if ($Incident) { 'incidents' } else { 'history' }
        $name = 'ae-' + $started.ToString("yyyyMMdd'T'HHmmssfff'Z'") + '-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.blg'
        $target = Join-Path (Join-Path $Policy.data_root $bucket) $name
        Move-Item -LiteralPath $live -Destination $target
        if (Test-Path -LiteralPath $live) { throw 'Active rename did not complete.' }
    }
    if (Test-Path -LiteralPath $statePath) { Remove-Item -LiteralPath $statePath -Force }
}

function Import-TelemetryArtifact($Policy, [string]$Directory, [string]$Path) {
    $runtime = Join-Path $Policy.data_root 'runtime'
    if (-not $Directory -or -not $Path) { throw 'import-artifact requires explicit SourceDirectory and ArtifactPath.' }
    $dir = Assert-TelemetryPath $Directory $runtime
    $source = Assert-TelemetryPath $Path $dir
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Import source is not a file.' }
    $file = Get-Item -LiteralPath $source
    if ($file.Extension.ToLowerInvariant() -notin @('.blg','.json','.txt','.log','.xml','.csv','.zip')) { throw 'Unsupported diagnostic artifact extension.' }
    # Deny concurrent writers while measuring and renaming; allow our same-volume rename.
    $handle = [IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Delete)
    try {
        Invoke-TelemetryPrune $Policy $handle.Length
        # The staging owner must preserve earliest-data UTC as CreationTimeUtc.
        $started = $file.CreationTimeUtc
        $name = 'ae-' + $started.ToString("yyyyMMdd'T'HHmmssfff'Z'") + '-' + [guid]::NewGuid().ToString('N').Substring(0,8) + $file.Extension.ToLowerInvariant()
        $target = Join-Path $Policy.data_root ('incidents\' + $name)
        Move-Item -LiteralPath $source -Destination $target
        if (Test-Path -LiteralPath $source) { throw 'Imported source rename did not complete.' }
    } finally { $handle.Dispose() }
    Invoke-TelemetryPrune $Policy
    return $target
}

function Assert-EvidenceFields($Value, [string[]]$Names) {
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) { throw 'Evidence object required.' }
    $actual = @($Value.PSObject.Properties.Name)
    if ($actual.Count -ne $Names.Count -or @($actual | Where-Object { $_ -cnotin $Names }).Count) { throw 'Unknown or missing evidence field.' }
}

function Get-EvidenceHash([IO.Stream]$Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

# This is a read-only source adapter. Admission, archive writing and expiry stay
# with the existing telemetry owner; runtime is never used as a staging area.
function Archive-TelemetryEvidence($Policy, [string]$Directory, [string]$ManifestPath) {
    Assert-EvidenceFields $Policy.evidence_archive @('max_files','max_source_bytes')
    $limits = $Policy.evidence_archive
    foreach ($value in @($limits.max_files,$limits.max_source_bytes)) {
        if ($value -isnot [int] -and $value -isnot [long]) { throw 'Evidence limits must be integers.' }
        if ($value -le 0) { throw 'Evidence limits must be positive.' }
    }
    if (-not $Directory -or -not $ManifestPath -or $Directory -notmatch '^[A-Za-z]:[\\/]') { throw 'Explicit absolute local evidence directory and manifest required.' }
    $dir = Assert-TelemetryPath $Directory $Directory
    if ($dir -eq [IO.Path]::GetPathRoot($dir).TrimEnd('\') -or -not (Test-Path -LiteralPath $dir -PathType Container)) { throw 'Evidence source must be a non-root directory.' }
    $root = [IO.Path]::GetFullPath($Policy.data_root).TrimEnd('\')
    foreach ($pair in @(@($dir,$root),@($root,$dir))) {
        if ($pair[0] -eq $pair[1] -or $pair[0].StartsWith($pair[1]+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence source overlaps diagnostics root.' }
    }
    if ($ManifestPath -notmatch '^[A-Za-z]:[\\/]') { throw 'Manifest requires an explicit absolute local path.' }
    $manifestFile = Assert-TelemetryPath $ManifestPath ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ManifestPath)))
    $handles = New-Object 'Collections.Generic.List[object]'
    $writer = $null; $zip = $null; $target = $null
    try {
        $mh = [IO.File]::Open($manifestFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $handles.Add($mh)
        if ($mh.Length -gt [Math]::Min([long]$limits.max_source_bytes,([long]$limits.max_files*4096+4096))) { throw 'Evidence manifest exceeds its derived bound.' }
        $reader = [IO.StreamReader]::new($mh,[Text.UTF8Encoding]::new($false,$true),$true,4096,$true)
        try { $manifest = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        Assert-EvidenceFields $manifest @('schema_version','captured_utc','retention_class','files')
        if ($manifest.schema_version -isnot [int] -or $manifest.schema_version -ne 1 -or $manifest.retention_class -cnotin @('ordinary','incident') -or $manifest.files -isnot [array]) { throw 'Invalid evidence manifest schema or retention class.' }
        if ($manifest.captured_utc -isnot [string] -or $manifest.captured_utc -cnotmatch '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?Z$') { throw 'Capture time must be explicit UTC.' }
        $started = [datetime]::Parse($manifest.captured_utc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AdjustToUniversal)
        $days = if ($manifest.retention_class -eq 'ordinary') { $Policy.retention.ordinary_days } else { $Policy.retention.incident_days }
        if ($started -gt [datetime]::UtcNow -or $started -le [datetime]::UtcNow.AddDays(-[double]$days).AddMinutes(15)) { throw 'Capture time is future or already expired.' }
        if ($manifest.files.Count -lt 1 -or $manifest.files.Count -gt $limits.max_files) { throw 'Evidence file count exceeds policy.' }
        $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $inputs = New-Object 'Collections.Generic.List[object]'
        $total = [long]0; $namesBytes = [long]0
        foreach ($item in $manifest.files) {
            Assert-EvidenceFields $item @('relative_path','length','sha256')
            $relative = $item.relative_path
            if ($relative -isnot [string] -or -not $relative -or [IO.Path]::IsPathRooted($relative) -or $relative.Contains('\') -or -not $seen.Add($relative)) { throw 'Invalid or duplicate evidence relative path.' }
            foreach ($segment in $relative.Split('/')) {
                if (-not $segment -or $segment -in @('.','..') -or $segment.TrimEnd(' ','.') -ne $segment -or $segment.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) { throw 'Evidence path traversal or invalid segment.' }
            }
            if (($item.length -isnot [int] -and $item.length -isnot [long]) -or $item.length -lt 0 -or $item.sha256 -isnot [string] -or $item.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid evidence length or hash.' }
            if ($item.length -gt [long]$limits.max_source_bytes-$total) { throw 'Evidence bytes exceed policy.' }
            $total += [long]$item.length
            $entryName = 'files/'+$relative
            $entryBytes = [Text.Encoding]::UTF8.GetByteCount($entryName)
            if ($entryBytes -gt 65535) { throw 'Evidence path exceeds ZIP name protocol.' }
            $namesBytes += $entryBytes
            $path = Assert-TelemetryPath (Join-Path $dir $relative) $dir
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Manifested evidence file missing.' }
            $handle = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            $handles.Add($handle)
            if ($handle.Length -ne [long]$item.length -or (Get-EvidenceHash $handle) -ne $item.sha256.ToLowerInvariant()) { throw 'Evidence source length/hash mismatch.' }
            $handle.Position = 0
            $info = Get-Item -LiteralPath $path -Force
            $inputs.Add([pscustomobject]@{ relative_path=$relative; length=[long]$item.length; sha256=$item.sha256.ToLowerInvariant(); creation_utc=$info.CreationTimeUtc.ToString('o'); last_write_utc=$info.LastWriteTimeUtc.ToString('o'); handle=$handle })
        }
        $provenance = [pscustomobject]@{ schema_version=1; captured_utc=$started.ToString('o'); retention_class=$manifest.retention_class; source_directory=$dir; files=@($inputs | Select-Object relative_path,length,sha256,creation_utc,last_write_utc) }
        $metadata = [Text.UTF8Encoding]::new($false).GetBytes(($provenance|ConvertTo-Json -Depth 6 -Compress))
        # NoCompression still has DEFLATE framing. This deliberately generous
        # bound covers framing, duplicate UTF-8 names, metadata and ZIP headers.
        $reserve = $total + $metadata.Length + [long][Math]::Ceiling(($total+$metadata.Length)/1024.0)*16 + $namesBytes*4 + ($inputs.Count+1)*1024L + 65536L
        Invoke-TelemetryPrune $Policy $reserve
        Add-Type -AssemblyName System.IO.Compression
        $bucket = if ($manifest.retention_class -eq 'ordinary') { 'history' } else { 'incidents' }
        $name = 'ae-'+$started.ToString("yyyyMMdd'T'HHmmssfff'Z'")+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.zip'
        $target = Assert-TelemetryPath (Join-Path $root ($bucket+'\'+$name)) $root
        # The parent ACL is intentionally not inherited: the actual DataRoot
        # grants other users access. FileStream applies this ACL at creation.
        $rootAcl = Get-Acl -LiteralPath $root
        $security = New-TelemetryStorageSecurity $Policy $false
        $rights = [Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write
        $writer = [IO.FileStream]::new($target,[IO.FileMode]::CreateNew,$rights,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$security)
        try {
            $zip = [IO.Compression.ZipArchive]::new($writer,[IO.Compression.ZipArchiveMode]::Create,$true,[Text.Encoding]::UTF8)
            $entry = $zip.CreateEntry('provenance.json',[IO.Compression.CompressionLevel]::NoCompression).Open()
            try { $entry.Write($metadata,0,$metadata.Length) } finally { $entry.Dispose() }
            foreach ($input in $inputs) {
                $entry = $zip.CreateEntry(('files/'+$input.relative_path),[IO.Compression.CompressionLevel]::NoCompression).Open()
                try { $input.handle.CopyTo($entry) } finally { $entry.Dispose() }
            }
        } finally {
            try { if ($zip) { $zip.Dispose() } }
            finally { $zip=$null; $writer.Dispose(); $writer=$null }
        }
        $archive = Get-Item -LiteralPath $target
        if ($archive.Length -gt $reserve) { throw 'Archive exceeded admission bound.' }
        $checkAcl = Get-Acl -LiteralPath $target
        $allowed = @('S-1-5-18','S-1-5-32-544',$Policy.storage_owner_sid)
        if (-not $checkAcl.AreAccessRulesProtected) { throw 'Archive ACL unexpectedly inherits.' }
        foreach ($rule in $checkAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -notin $allowed) { throw 'Archive ACL is not private.' }
        }
        $readBack = [IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $zip = [IO.Compression.ZipArchive]::new($readBack,[IO.Compression.ZipArchiveMode]::Read,$true,[Text.Encoding]::UTF8)
            if ($zip.Entries.Count -ne $inputs.Count+1) { throw 'Archive verification entry count mismatch.' }
            foreach ($input in $inputs) {
                $entry = $zip.GetEntry('files/'+$input.relative_path)
                if ($null -eq $entry -or $entry.Length -ne $input.length) { throw 'Archive verification entry length mismatch.' }
                $stream = $entry.Open()
                try { if ((Get-EvidenceHash $stream) -ne $input.sha256) { throw 'Archive verification entry hash mismatch.' } } finally { $stream.Dispose() }
            }
            $stream = $zip.GetEntry('provenance.json').Open()
            $expected = [IO.MemoryStream]::new($metadata,$false)
            try { if ((Get-EvidenceHash $stream) -ne (Get-EvidenceHash $expected)) { throw 'Archive provenance verification failed.' } } finally { $stream.Dispose(); $expected.Dispose() }
        } finally {
            try { if ($zip) { $zip.Dispose() } }
            finally { $zip=$null; $readBack.Dispose() }
        }
        Invoke-TelemetryPrune $Policy
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw 'Archive expired during verification.' }
        return [pscustomobject]@{ archive_path=$target; verified=$true; source_files=$inputs.Count; source_bytes=$total; archive_bytes=$archive.Length; captured_utc=$started.ToString('o'); retention_class=$manifest.retention_class; source_preserved=$true; private_acl=$true }
    } finally {
        try { if ($zip) { $zip.Dispose() } }
        finally {
            try { if ($writer) { $writer.Dispose() } }
            finally { foreach ($handle in $handles) { $handle.Dispose() } }
        }
    }
}

function Get-TelemetryStatus($Policy) {
    $storage=Invoke-TelemetryStoreSnapshot {
    $rows = @(Get-TelemetryInventory $Policy)
    $gaps = @()
    if (-not (Test-Path -LiteralPath $Policy.data_root -PathType Container)) { $gaps += 'StorageRootMissing' }
    else {
        $paths = @(Get-TelemetryStoragePaths $Policy)
        if (@($paths|Where-Object {-not (Test-TelemetryStorageAccess $Policy $_.Path $_.Protected)}).Count) { $gaps += 'StorageAclDrift' }
        foreach ($name in @('active','history','incidents','runtime')) { if (-not (Test-Path -LiteralPath (Join-Path $Policy.data_root $name) -PathType Container)) { $gaps += 'StorageDirectoryMissing'; break } }
    }
    [pscustomobject]@{Rows=$rows;Gaps=$gaps}
    }
    $rows=@($storage.Rows); $gaps=@($storage.Gaps)
    $dcs = Get-TelemetryCollector $Policy
    $state = if ($null -eq $dcs) { 'NotInstalled' } elseif ($dcs.Status -eq 1) { 'Running' } elseif ($dcs.Status -eq 0) { 'Stopped' } else { 'Transitioning' }
    if ($state -ne 'Running') { $gaps += "Collector:$state" }
    if ($null -ne $dcs) {
        try { Assert-TelemetryCollectorConfiguration $Policy $dcs } catch { $gaps += 'CollectorConfigurationDrift' }
    }
    $active = Get-TelemetryBytes $rows @('active')
    $closed = Get-TelemetryBytes $rows @('history','incidents')
    $runtime = Get-TelemetryBytes $rows @('runtime')
    if ($active -gt [long]$Policy.retention.active_reserved_bytes) { $gaps += 'ActiveBudgetExceeded' }
    if ($closed -gt [long]$Policy.retention.closed_max_bytes) { $gaps += 'ClosedBudgetExceeded' }
    if ($runtime -gt [long]$Policy.retention.runtime_max_bytes) { $gaps += 'RuntimeBudgetExceeded' }
    [pscustomobject]@{ collector=$Policy.monitor.collector_name; collector_state=$state; data_root=$Policy.data_root; active_bytes=$active; closed_bytes=$closed; runtime_bytes=$runtime; discovered_total_bytes=($active+$closed+$runtime); hard_limit_bytes=[long]$Policy.retention.total_bytes; reserved_upper_bytes=([long]$Policy.retention.active_reserved_bytes+$closed+[long]$Policy.retention.runtime_max_bytes+[long]$Policy.retention.margin_bytes); retained_files=$rows.Count; gaps=$gaps; checked_utc=[datetime]::UtcNow.ToString('o') }
}

function Get-TelemetryTaskNames($Policy) { return @(($Policy.monitor.collector_name+'-Maintenance'), ($Policy.monitor.collector_name+'-Incident')) }

function New-TelemetryTaskDefinitions($Policy, [string]$PolicyFile) {
    $names = @(Get-TelemetryTaskNames $Policy)
    $engine = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable -Hidden
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $common = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $script:TelemetryScriptPath + '" -PolicyPath "' + [IO.Path]::GetFullPath($PolicyFile) + '" -Command '
    $action = New-ScheduledTaskAction -Execute $engine -Argument ($common+'maintenance')
    $triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15)))
    $maintenance = New-ScheduledTask -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Description $script:TelemetryOwner
    $eventClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
    $subscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-Resource-Exhaustion-Detector/Operational"><Select Path="Microsoft-Windows-Resource-Exhaustion-Detector/Operational">*[System[Provider[@Name="Microsoft-Windows-Resource-Exhaustion-Detector"] and EventID=1003]]</Select></Query></QueryList>'
    $eventTrigger = New-CimInstance -CimClass $eventClass -Property @{Enabled=$true;Subscription=$subscription} -ClientOnly
    $eventAction = New-ScheduledTaskAction -Execute $engine -Argument ($common+'incident')
    $incident = New-ScheduledTask -Action $eventAction -Trigger $eventTrigger -Principal $principal -Settings $settings -Description $script:TelemetryOwner
    return @([pscustomobject]@{Name=$names[0];Definition=$maintenance},[pscustomobject]@{Name=$names[1];Definition=$incident})
}

function Install-TelemetryTasks($Policy, [string]$PolicyFile) {
    $definitions = @(New-TelemetryTaskDefinitions $Policy $PolicyFile)
    foreach ($item in $definitions) {
        $existing = Get-ScheduledTask -TaskPath '\' -TaskName $item.Name -ErrorAction SilentlyContinue
        if ($existing -and $existing.Description -ne $script:TelemetryOwner) { throw "Refusing foreign scheduled task: $($item.Name)" }
    }
    foreach ($item in $definitions) { Register-ScheduledTask -TaskName $item.Name -InputObject $item.Definition -Force | Out-Null }
}

function Invoke-TelemetryCommand($Policy, [string]$Operation, [string]$PolicyFile, [string]$Directory, [string]$Path) {
    $hash = [Security.Cryptography.SHA256]::Create()
    $key = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Policy.data_root.ToLowerInvariant())))).Replace('-','').Substring(0,24)
    $mutex = New-Object Threading.Mutex($false,('Global\AgentExecutionTelemetry-'+$key))
    $locked = $false
    try {
        try { $locked = $mutex.WaitOne([timespan]::FromSeconds(20)) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (-not $locked) { throw 'Telemetry owner busy; no concurrent mutation.' }
        if ($Operation -eq 'status') { return Get-TelemetryStatus $Policy }
        Initialize-TelemetryRoot $Policy
        if ($Operation -eq 'initialize-storage') { return [pscustomobject]@{storage_initialized=$true;data_root=$Policy.data_root;storage_owner_sid=$Policy.storage_owner_sid} }
        if ($Operation -eq 'archive-evidence') {
            try { return Archive-TelemetryEvidence $Policy $Directory $Path }
            catch {
                $archiveError = $_
                # Bad source input must not stop a healthy unrelated collector.
                # Fail closed only when diagnostics inventory/budgets are broken.
                try {
                    $rows = @(Get-TelemetryInventory $Policy)
                    if ((Get-TelemetryBytes $rows @('active')) -gt $Policy.retention.active_reserved_bytes -or (Get-TelemetryBytes $rows @('runtime')) -gt $Policy.retention.runtime_max_bytes -or (Get-TelemetryBytes $rows @('history','incidents')) -gt $Policy.retention.closed_max_bytes) { throw 'Archive diagnostics budget invalid.' }
                } catch { try { Stop-TelemetryCollector $Policy } catch { } }
                throw $archiveError
            }
        }
        try {
            Invoke-TelemetryPrune $Policy
            switch ($Operation) {
                'maintenance' {
                    # Runtime receipts/requests expire even when no more agent commands run.
                    # Both principals use the same installation-wide store mutex.
                    if ($Policy.PSObject.Properties.Name -contains 'execution') {
                        $binary = [string]$Policy.execution.binary_name
                        if ($binary -notmatch '^agent-exec\.v[0-9]+\.exe$') { throw 'Invalid execution artifact identity.' }
                        $runner = Join-Path (Split-Path -Parent $script:TelemetryScriptPath) $binary
                        if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) { throw 'Runtime retention owner is not installed.' }
                        & $runner maintain --policy ([IO.Path]::GetFullPath($PolicyFile))
                        if ($LASTEXITCODE -ne 0) { throw 'Runtime retention failed; observation remains stopped.' }
                    }
                    $dcs = Get-TelemetryCollector $Policy
                    if ($null -eq $dcs) { throw 'Collector is not installed.' }
                    $statePath = Join-Path $Policy.data_root 'active\current.json'
                    if ($dcs.Status -eq 0) { Move-TelemetryActive $Policy $false }
                    elseif (Test-Path -LiteralPath $statePath) {
                        $started = [datetime](Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json).started_utc
                        if ($started.ToUniversalTime() -le [datetime]::UtcNow.AddHours(-[double]$Policy.monitor.period_hours)) { Move-TelemetryActive $Policy $false }
                    } else { throw 'Running collector has no earliest-data state.' }
                    Start-TelemetryCollector $Policy
                }
                'incident' { Move-TelemetryActive $Policy $true; Start-TelemetryCollector $Policy }
                'import-artifact' { Import-TelemetryArtifact $Policy $Directory $Path | Out-Null }
                'install' { New-TelemetryCollector $Policy; Install-TelemetryTasks $Policy $PolicyFile }
                'uninstall' {
                    Stop-TelemetryCollector $Policy
                    foreach ($name in Get-TelemetryTaskNames $Policy) {
                        $task = Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue
                        if ($task) {
                            if ($task.Description -ne $script:TelemetryOwner) { throw "Refusing foreign scheduled task: $name" }
                            Unregister-ScheduledTask -TaskName $name -Confirm:$false
                        }
                    }
                    if ($null -ne (Get-TelemetryCollector $Policy)) { Invoke-TelemetryLogman @('delete',$Policy.monitor.collector_name) }
                }
            }
            Invoke-TelemetryPrune $Policy
            return Get-TelemetryStatus $Policy
        } catch {
            # A quota/cleanup/identity failure must not leave an owned writer running.
            try { Stop-TelemetryCollector $Policy } catch { }
            $failure = [pscustomobject]@{ time_utc=[datetime]::UtcNow.ToString('o'); operation=$Operation; error_type=$_.Exception.GetType().Name; message=$_.Exception.Message.Substring(0,[Math]::Min(800,$_.Exception.Message.Length)) } | ConvertTo-Json -Compress
            if ([Text.Encoding]::UTF8.GetByteCount($failure) -le 4096) {
                $failurePath = Assert-TelemetryPath (Join-Path $Policy.data_root 'active\last-error.json') $Policy.data_root
                [IO.File]::WriteAllText($failurePath,$failure,[Text.UTF8Encoding]::new($false))
            }
            throw
        }
    } finally {
        if ($locked) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
        $hash.Dispose()
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $policy = Get-TelemetryPolicy $PolicyPath
    Invoke-TelemetryCommand $policy $Command $PolicyPath $SourceDirectory $ArtifactPath | ConvertTo-Json -Depth 5 -Compress
}
