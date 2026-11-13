[CmdletBinding(SupportsShouldProcess=$true)]
param()
$ErrorActionPreference='Stop'
$manifest=Join-Path $PSScriptRoot 'rollback\files.json'
$files=Get-Content -LiteralPath $manifest -Encoding UTF8 -Raw|ConvertFrom-Json
# Preflight the entire restore before modifying a global source.
foreach($f in $files){
    if(-not $f.installed_sha256){throw 'Incomplete installation snapshot; inspect before rollback.'}
    if(-not(Test-Path -LiteralPath $f.path) -or (Get-FileHash -LiteralPath $f.path -Algorithm SHA256).Hash -ne $f.installed_sha256){throw 'Global file changed independently; automatic restore refused.'}
    if($f.existed -and (Get-FileHash -LiteralPath $f.backup -Algorithm SHA256).Hash -ne $f.original_sha256){throw 'Rollback source checksum mismatch.'}
}
if(-not $PSCmdlet.ShouldProcess('Global agent configuration and owned PLA/tasks','Restore exact original configuration; preserve diagnostics')){return}
& (Join-Path $PSScriptRoot 'telemetry.ps1') -Command uninstall
foreach($f in $files){if($f.existed){[IO.File]::Copy($f.backup,$f.path,$true)}else{[IO.File]::Delete($f.path)}}
'Original global configuration restored; owned diagnostics retained.'
