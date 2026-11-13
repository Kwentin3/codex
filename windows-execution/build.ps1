[CmdletBinding()]
param([ValidatePattern('^agent-exec\.v[0-9]+\.exe$')][string]$Name='agent-exec.v1.exe')
$ErrorActionPreference='Stop'
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not(Test-Path -LiteralPath $compiler -PathType Leaf)){throw 'Required .NET Framework compiler is absent.'}
$sources=@('AgentExec.cs','ShellCommand.cs','RunStore.cs','WinJob.cs')|ForEach-Object{Join-Path $PSScriptRoot $_}
$output=Join-Path $PSScriptRoot $Name
if(Test-Path -LiteralPath $output){throw 'Build identities are immutable; choose a new versioned filename.'}
& $compiler /nologo /langversion:5 /codepage:65001 /target:exe /platform:x64 /optimize+ /r:System.Web.Extensions.dll /r:System.Management.dll ('/out:'+$output) @sources
if($LASTEXITCODE -ne 0){throw 'Agent execution controller compilation failed.'}
Get-FileHash -LiteralPath $output -Algorithm SHA256
