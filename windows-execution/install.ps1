[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$utf8=[Text.UTF8Encoding]::new($false)
$root=$PSScriptRoot
$backup=Join-Path $root 'rollback'
$manifest=Join-Path $backup 'files.json'
if(Test-Path -LiteralPath $manifest){throw 'Installation snapshot already exists; use status/maintenance or review the existing installation.'}
$policy=Get-Content -LiteralPath (Join-Path $root 'policy.json') -Encoding UTF8 -Raw|ConvertFrom-Json
if($policy.execution.binary_name -notmatch '^agent-exec\.v[0-9]+\.exe$' -or -not(Test-Path -LiteralPath (Join-Path $root $policy.execution.binary_name))){throw 'Build the reviewed versioned controller before installation.'}
if(-not(Test-Path -LiteralPath (Join-Path $root 'agent-exec.v2.exe') -PathType Leaf)){throw 'Stage the reviewed AGY hook adapter before installing hooks.'}
. (Join-Path $root 'telemetry.ps1')
$storagePolicy=Get-TelemetryPolicy (Join-Path $root 'policy.json')
Invoke-TelemetryCommand $storagePolicy 'initialize-storage' (Join-Path $root 'policy.json') $null $null | Out-Null
$profileRoot=[Environment]::GetFolderPath('UserProfile')
$files=@(
    @{key='codex-agents';path=(Join-Path $profileRoot '.codex\AGENTS.md')},
    @{key='agy-rules';path=(Join-Path $profileRoot '.gemini\GEMINI.md')},
    @{key='codex-hooks';path=(Join-Path $profileRoot '.codex\hooks.json')},
    @{key='agy-hooks';path=(Join-Path $profileRoot '.gemini\config\hooks.json')}
)
foreach($f in $files){
    $cursor=[IO.Path]::GetFullPath($f.path)
    while($cursor){
        if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Global configuration through a reparse point is not supported.'}
        $next=[IO.Path]::GetDirectoryName($cursor);if($next -eq $cursor){break};$cursor=$next
    }
    if((Test-Path -LiteralPath $f.path) -and (Get-Item -LiteralPath $f.path).Length -gt 65536){throw 'Global source exceeds backup bound.'}
}
foreach($f in $files|Where-Object{$_.key -like '*hooks'}){if(Test-Path -LiteralPath $f.path){throw 'Existing hooks require an explicit preserving merge; no global files were changed.'}}
New-Item -ItemType Directory -Path $backup -Force|Out-Null
foreach($f in $files){
    $f.existed=Test-Path -LiteralPath $f.path
    $f.backup=Join-Path $backup ($f.key+'.original')
    if($f.existed){[IO.File]::Copy($f.path,$f.backup,$false);$f.original_sha256=(Get-FileHash -LiteralPath $f.path -Algorithm SHA256).Hash}
}
# Save recovery metadata before any global write.
[IO.File]::WriteAllText($manifest,($files|ConvertTo-Json -Depth 4),$utf8)
$block=@'

<!-- windows-agent-execution -->
- Для всех локальных shell-команд на этой Windows-машине, во всех проектах,
  используй общий исполнитель по `C:/Users/Администратор/.agents/windows-execution/README.md`.
  Весь полезный код передавай внутрь managed-команды, задавай владельца и срок;
  для тяжёлой работы используй owner `heavy:имя`, для намеренной фоновой —
  `background:имя` с явным сроком. Не обходи hook, Job или ограничения через
  другой shell, detached launch, scheduler либо внешнюю службу.
  После timeout/cancel/unknown проверь завершение своего RunId до повтора.
  Лимиты и retention принадлежат общему policy.json; не создавай вторых писателей
  вне его бюджета. Native approval/sandbox остаются владельцами разрешений.
  Для первого чтения README используй эту готовую managed-команду (одна строка):
  `C:/Users/Администратор/.agents/windows-execution/agent-exec.v1.exe inline --owner readme --shell powershell --timeout 20 --command-base64 R2V0LUNvbnRlbnQgLUxpdGVyYWxQYXRoICdDOi9Vc2Vycy/QkNC00LzQuNC90LjRgdGC0YDQsNGC0L7RgC8uYWdlbnRzL3dpbmRvd3MtZXhlY3V0aW9uL1JFQURNRS5tZCcgLUVuY29kaW5nIFVURjggLVJhdw==`
  Для локальных процессов через MCP/browser и другие tools также сначала
  проверь владельца, лимиты и адресную остановку. Если они не подтверждены,
  запускай работу через общий исполнитель; обходного маршрута не используй.
  Службы клиента и удалённые среды сохраняют собственных владельцев:
  их ограничения нужно проверить до запуска новой работы.
<!-- /windows-agent-execution -->
'@
try{
    foreach($f in $files){
        if($f.existed -and (Get-FileHash -LiteralPath $f.path -Algorithm SHA256).Hash -ne $f.original_sha256){throw 'Global source changed after snapshot; preserving independent changes.'}
        switch($f.key){
            'codex-agents' {$old=if($f.existed){[IO.File]::ReadAllText($f.path,[Text.Encoding]::UTF8)}else{''};if($old.Contains('<!-- windows-agent-execution -->')){throw 'Existing control instruction needs preserving review.'};[IO.File]::WriteAllText($f.path,$old.TrimEnd()+"`n"+$block+"`n",$utf8)}
            'agy-rules' {$old=if($f.existed){[IO.File]::ReadAllText($f.path,[Text.Encoding]::UTF8)}else{''};[IO.File]::WriteAllText($f.path,$old.TrimEnd()+"`n"+$block+"`n",$utf8)}
            'codex-hooks' {[IO.File]::Copy((Join-Path $root 'hooks.codex.json'),$f.path,$false)}
            'agy-hooks' {[IO.File]::Copy((Join-Path $root 'hooks.agy.json'),$f.path,$false)}
        }
        $f.installed_sha256=(Get-FileHash -LiteralPath $f.path -Algorithm SHA256).Hash
        [IO.File]::WriteAllText($manifest,($files|ConvertTo-Json -Depth 4),$utf8)
    }
    $files|ForEach-Object{[pscustomobject]@{key=$_.key;path=$_.path;installed_sha256=$_.installed_sha256}}|ConvertTo-Json -Compress
}catch{
    # Only restore bytes this installer actually wrote; preserve any independent edit.
    foreach($f in $files){
        if($f.installed_sha256 -and (Test-Path -LiteralPath $f.path) -and (Get-FileHash -LiteralPath $f.path -Algorithm SHA256).Hash -eq $f.installed_sha256){
            if($f.existed){[IO.File]::Copy($f.backup,$f.path,$true)}else{[IO.File]::Delete($f.path)}
        }
    }
    throw
}
