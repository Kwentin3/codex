param([string]$TelemetryPath,[string]$PolicyPath)
$ErrorActionPreference = 'Stop'
$package = Split-Path -Parent $PSScriptRoot
if (-not $TelemetryPath) { $TelemetryPath=Join-Path $package 'telemetry.ps1' }
if (-not $PolicyPath) { $PolicyPath=Join-Path $package 'policy.json' }
. $TelemetryPath -PolicyPath $PolicyPath
$installed = Get-TelemetryPolicy $PolicyPath
$testRoot = Join-Path (Split-Path -Parent $installed.data_root) ('AgentExecutionEvidenceTest-'+[guid]::NewGuid().ToString('N'))
$expectedRoot = [IO.Path]::GetFullPath($testRoot)
$checks = New-Object 'Collections.Generic.List[string]'
$junction = $null; $script:stopCalls = 0
# No native collector or scheduled task is touched by these tests. This guard
# proves rejected archive inputs do not enter the normal collector failure path.
function Stop-TelemetryCollector($Policy) { $script:stopCalls++; throw 'Unexpected native stop in isolated archive test.' }
function Assert-That([bool]$Value,[string]$Message) { if (-not $Value) { throw "ASSERT: $Message" }; $checks.Add($Message) }
function Clone-Policy { return ($installed | ConvertTo-Json -Depth 8 | ConvertFrom-Json) }
function Save-Manifest($Value) { [IO.File]::WriteAllText($manifestPath,($Value|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false)) }
function New-Manifest([string]$Class,[datetime]$Capture) {
    return [pscustomobject]@{ schema_version=1; captured_utc=$Capture.ToUniversalTime().ToString('o'); retention_class=$Class; files=@($relativeNames | ForEach-Object {
        $file = Get-Item -LiteralPath (Join-Path $source $_)
        [pscustomobject]@{ relative_path=$_; length=[long]$file.Length; sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    }) }
}
function Archive($Policy,$Manifest) {
    Save-Manifest $Manifest
    return Invoke-TelemetryCommand $Policy 'archive-evidence' '' $source $manifestPath
}
function Assert-Rejected($Policy,$Manifest,[string]$Message,[string]$Directory=$source) {
    Save-Manifest $Manifest
    $before = @(Get-TelemetryInventory $Policy).Count
    $hashes = @($relativeNames | ForEach-Object { (Get-FileHash -LiteralPath (Join-Path $source $_)).Hash }) -join ','
    $rejected = $false
    try { Invoke-TelemetryCommand $Policy 'archive-evidence' '' $Directory $manifestPath | Out-Null } catch { $rejected=$true }
    Assert-That $rejected $Message
    Assert-That (@(Get-TelemetryInventory $Policy).Count -eq $before) "$Message before archive payload"
    $after = @($relativeNames | ForEach-Object { (Get-FileHash -LiteralPath (Join-Path $source $_)).Hash }) -join ','
    Assert-That ($after -eq $hashes) "$Message preserves source"
}
function Read-Provenance([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $archive = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read)
    try {
        $reader = [IO.StreamReader]::new($archive.GetEntry('provenance.json').Open(),[Text.Encoding]::UTF8)
        try { return ($reader.ReadToEnd()|ConvertFrom-Json) } finally { $reader.Dispose() }
    } finally { $archive.Dispose(); $stream.Dispose() }
}
try {
    if (Test-Path -LiteralPath $testRoot) { throw 'Fresh isolated fixture root already exists.' }
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $source = Join-Path $testRoot 'source'
    New-Item -ItemType Directory -Path (Join-Path $source 'подкаталог') | Out-Null
    $manifestPath = Join-Path $testRoot 'manifest.json'
    $relativeNames = @('подкаталог/снимок.jsonl','binary.pids','empty.stdout')
    [IO.File]::WriteAllText((Join-Path $source $relativeNames[0]),"строка`nисторическое событие 2026-09-16`n",[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllBytes((Join-Path $source $relativeNames[1]),[byte[]](0..255))
    [IO.File]::WriteAllBytes((Join-Path $source $relativeNames[2]),[byte[]]@())
    $policy = Clone-Policy
    $policy.data_root = Join-Path $testRoot 'data'
    Initialize-TelemetryRoot $policy
    $capture = [datetime]::UtcNow.AddDays(-1)
    $ordinary = New-Manifest ordinary $capture
    $first = Archive $policy $ordinary
    Assert-That ($first.verified -and $first.source_preserved -and $first.source_files -eq 3) 'mixed extensions archived and verified'
    Assert-That ((Split-Path (Split-Path $first.archive_path -Parent) -Leaf) -eq 'history') 'ordinary archive uses history'
    $prov = Read-Provenance $first.archive_path
    Assert-That ($prov.files.Count -eq 3 -and $prov.files[0].relative_path -ceq $relativeNames[0]) 'Unicode paths preserved in provenance'
    Assert-That ($prov.captured_utc -eq $ordinary.captured_utc -and $first.captured_utc -eq $ordinary.captured_utc) 'original collection start preserved'
    foreach ($item in $prov.files) {
        $file = Get-Item -LiteralPath (Join-Path $source $item.relative_path)
        Assert-That ($item.creation_utc -eq $file.CreationTimeUtc.ToString('o') -and $item.last_write_utc -eq $file.LastWriteTimeUtc.ToString('o')) 'real source timestamps recorded'
    }
    $stream = [IO.File]::OpenRead($first.archive_path)
    $zip = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read)
    try {
        Assert-That ($zip.Entries.Count -eq 4) 'exact payload and provenance entry count'
        foreach ($item in $ordinary.files) {
            $entry = $zip.GetEntry('files/'+$item.relative_path)
            $payload = $entry.Open()
            $memory = [IO.MemoryStream]::new()
            try {
                $payload.CopyTo($memory)
                $expected = [IO.File]::ReadAllBytes((Join-Path $source $item.relative_path))
                Assert-That ([Convert]::ToBase64String($memory.ToArray()) -ceq [Convert]::ToBase64String($expected)) 'ZIP bytes equal independent source bytes'
            } finally { $payload.Dispose(); $memory.Dispose() }
        }
    } finally { $zip.Dispose(); $stream.Dispose() }
    $acl = Get-Acl -LiteralPath $first.archive_path
    Assert-That $acl.AreAccessRulesProtected 'ZIP ACL protected at creation'
    $sids = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {$_.IdentityReference.Value})
    Assert-That (@($sids|Where-Object {$_ -notin @('S-1-5-18','S-1-5-32-544',$policy.storage_owner_sid)}).Count -eq 0) 'ZIP ACL limited to SYSTEM Admin and policy operator SID'
    $incident = Archive $policy (New-Manifest incident ([datetime]::UtcNow.AddDays(-8)))
    Assert-That ((Split-Path (Split-Path $incident.archive_path -Parent) -Leaf) -eq 'incidents') 'eight-day incident archive admitted to incidents'
    $row = Get-TelemetryInventory $policy | Where-Object Path -eq $first.archive_path
    Assert-That ([Math]::Abs(($row.StartedUtc-$capture).TotalMilliseconds) -lt 1) 'archive filename age comes from capture not staging time'
    Assert-Rejected $policy (New-Manifest ordinary ([datetime]::UtcNow.AddDays(-8))) 'ordinary older than seven days rejected'
    Assert-Rejected $policy (New-Manifest incident ([datetime]::UtcNow.AddDays(-31))) 'incident older than thirty days rejected'
    Assert-Rejected $policy (New-Manifest ordinary ([datetime]::UtcNow.AddHours(1))) 'future capture rejected'
    $bad = New-Manifest ordinary $capture
    [IO.File]::WriteAllBytes((Join-Path $source 'binary.pids'),[byte[]](255..0))
    Assert-Rejected $policy $bad 'changed real source behind manifest rejected'
    $bad = New-Manifest ordinary $capture; $bad.files[0].sha256='0'*64
    Assert-Rejected $policy $bad 'wrong hash rejected'
    $bad = New-Manifest ordinary $capture; $bad.files[0].relative_path='../outside.txt'
    Assert-Rejected $policy $bad 'relative path escape rejected'
    $bad = New-Manifest ordinary $capture; $bad.files[0].relative_path='C:/Windows/win.ini'
    Assert-Rejected $policy $bad 'absolute entry rejected'
    $bad = New-Manifest ordinary $capture; $bad|Add-Member -NotePropertyName unexpected -NotePropertyValue 1
    Assert-Rejected $policy $bad 'unknown manifest field rejected'
    $bad = New-Manifest ordinary $capture; $bad.files[0]|Add-Member -NotePropertyName unexpected -NotePropertyValue 1
    Assert-Rejected $policy $bad 'unknown file field rejected'
    $bad = New-Manifest ordinary $capture; $bad.files[0].length=[long]$policy.evidence_archive.max_source_bytes+1
    Assert-Rejected $policy $bad 'oversize declaration rejected'
    $bad = New-Manifest ordinary $capture; $bad.files=@($bad.files[0])*257
    Assert-Rejected $policy $bad 'file count above policy rejected'
    $bad = New-Manifest ordinary $capture
    Assert-Rejected $policy $bad 'volume root rejected' ([IO.Path]::GetPathRoot($source))
    Assert-Rejected $policy $bad 'diagnostics overlap rejected' $policy.data_root
    Assert-Rejected $policy $bad 'drive-relative source rejected' 'D:relative'
    $bad = New-Manifest ordinary $capture; $bad.schema_version=$true
    Assert-Rejected $policy $bad 'boolean schema version rejected'
    $outside = Join-Path $testRoot 'outside'
    New-Item -ItemType Directory -Path $outside | Out-Null
    [IO.File]::WriteAllText((Join-Path $outside 'sentinel.txt'),'preserve fixture')
    $junction = Join-Path $source 'linked'
    New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
    $bad = New-Manifest ordinary $capture; $bad.files[0].relative_path='linked/sentinel.txt'
    Assert-Rejected $policy $bad 'reparse ancestor rejected'
    Assert-That ([IO.File]::ReadAllText((Join-Path $outside 'sentinel.txt')) -eq 'preserve fixture') 'reparse target preserved'
    $quota = Clone-Policy; $quota.data_root=Join-Path $testRoot 'quota'; $quota.retention.closed_max_bytes=1000
    Initialize-TelemetryRoot $quota
    Assert-Rejected $quota (New-Manifest ordinary $capture) 'admission above closed quota rejected'
    $evict = Clone-Policy; $evict.data_root=Join-Path $testRoot 'evict'; $evict.retention.closed_max_bytes=100000
    Initialize-TelemetryRoot $evict
    $old = Join-Path $evict.data_root ('history/ae-'+[datetime]::UtcNow.AddDays(-2).ToString("yyyyMMdd'T'HHmmssfff'Z'")+'-abcdef01.txt')
    [IO.File]::WriteAllBytes($old,[byte[]]::new(60000))
    $admitted = Archive $evict (New-Manifest ordinary $capture)
    Assert-That ((-not (Test-Path -LiteralPath $old)) -and $admitted.verified) 'existing telemetry prune creates room before archive admission'
    Assert-That ((Get-TelemetryBytes @(Get-TelemetryInventory $evict) @('history','incidents')) -le $evict.retention.closed_max_bytes) 'archive remains inside shared closed quota'
    # A readback failure occurs after ZIP creation: its bounded, private artifact
    # stays in the existing quota, all handles close and no success is reported.
    $partial = Clone-Policy; $partial.data_root=Join-Path $testRoot 'partial'
    Initialize-TelemetryRoot $partial
    $hashOwner = ${function:Get-EvidenceHash}; $script:hashCalls=0; $failed=$false
    function Get-EvidenceHash([IO.Stream]$Stream) {
        $script:hashCalls++
        if ($script:hashCalls -eq 4) { throw 'Injected archive readback failure.' }
        return (& $hashOwner $Stream)
    }
    try { Archive $partial (New-Manifest ordinary $capture) | Out-Null } catch { $failed=$true }
    finally { Set-Item -Path function:Get-EvidenceHash -Value $hashOwner }
    Assert-That ($failed -and $script:hashCalls -eq 4) 'failed readback never reports successful import'
    $partialRows = @(Get-TelemetryInventory $partial)
    Assert-That ($partialRows.Count -eq 1 -and $partialRows[0].Bytes -le $partial.retention.closed_max_bytes) 'unverified ZIP remains bounded in existing quota'
    foreach ($path in @($partialRows[0].Path)+@($relativeNames|ForEach-Object {Join-Path $source $_})) {
        $exclusive = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $exclusive.Dispose()
    }
    Assert-That $true 'archive and source handles released after verification failure'
    $policy.retention.ordinary_days=0.5
    Invoke-TelemetryPrune $policy
    Assert-That (-not (Test-Path -LiteralPath $first.archive_path)) 'ZIP ordinary retention enforced by existing prune'
    Assert-That (Test-Path -LiteralPath $incident.archive_path) 'incident ZIP survives ordinary expiry'
    Assert-That ($script:stopCalls -eq 0) 'invalid input and healthy quota rejection never stop collector'
    [pscustomobject]@{ result='PASS'; assertions=$checks.Count; source_files=3; archive_bytes=$first.archive_bytes; checks=$checks; fixture_root=$testRoot }|ConvertTo-Json -Depth 5 -Compress
} finally {
    if ($junction -and (Test-Path -LiteralPath $junction)) { [IO.Directory]::Delete($junction) }
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if ($resolved -ne $expectedRoot -or (Split-Path $resolved -Leaf) -notmatch '^AgentExecutionEvidenceTest-[0-9a-f]{32}$' -or (Split-Path $resolved -Parent) -ne (Split-Path -Parent $installed.data_root)) { throw 'Fixture cleanup containment failed.' }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
