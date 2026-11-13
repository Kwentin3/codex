"""Small real native gate/managed-shell checks; no model or load calls."""
import base64
import json
import os
import pathlib
import subprocess
import tempfile
import time

HOME = pathlib.Path(__file__).resolve().parents[1]
EXE = str(HOME / 'agent-exec.v1.exe')
CODEX_GATE = EXE
AGY_GATE = str(HOME / 'agent-exec.v2.exe')
AGY_PASS = {'decision': 'allow'}
PORTABLE = EXE.replace('\\', '/')
PS = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
CWD = str(HOME)
ENV = dict(os.environ, AGENT_EXEC_TEST='bounded-value')
checks = []


def invoke(argv, **kwargs):
    return subprocess.run(argv, cwd=CWD, env=ENV, capture_output=True, timeout=15, **kwargs)


def command_line(source, owner, shell='powershell', seconds=10):
    encoded = base64.b64encode(source.encode()).decode()
    return f'{PORTABLE} inline --owner {owner} --shell {shell} --timeout {seconds} --command-base64 {encoded}'


def gate_payload(payload, agent='codex', ensure_ascii=False):
    executable = CODEX_GATE if agent == 'codex' else AGY_GATE
    result = invoke([executable, 'hook', agent],
                    input=json.dumps(payload, ensure_ascii=ensure_ascii).encode('utf-8'))
    assert result.returncode == 0 and not result.stderr, result.stderr
    return json.loads(result.stdout.decode('utf-8-sig'))


def gate(command, agent='codex', ensure_ascii=False):
    if agent == 'codex':
        payload = {'tool_name': 'Bash', 'tool_input': {'command': command}, 'cwd': CWD}
    else:
        payload = {'toolCall': {'name': 'run_command', 'args': {'CommandLine': command, 'Cwd': CWD}}}
    return gate_payload(payload, agent, ensure_ascii)


def receipt(owner):
    matches = []
    for p in pathlib.Path(r'D:\AgentExecutionDiagnostics\runtime\receipts').glob('*.jsonl'):
        for line in p.open(encoding='utf-8-sig'):
            value = json.loads(line)
            if value.get('owner') == owner:
                matches.append(value)
    assert matches, ('receipt absent', owner)
    return max(matches, key=lambda x: x['completed_utc_ticks'])


baseline_state = json.loads(invoke([EXE, 'status']).stdout)


def check(label, source, expected_code=0, expected_text=None, shell='powershell'):
    owner = 'integration:' + label
    command = command_line(source, owner, shell)
    assert gate(command) == {} and gate(command, 'agy') == AGY_PASS, label
    result = invoke([PS, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command])
    # The native model submitted an executable invocation; Windows PowerShell's
    # normal nonzero-native-exit normalization applies. Exact child code is retained.
    assert result.returncode == (0 if expected_code == 0 else 1), (label, result.returncode, result.stderr[:500])
    saved = receipt(owner)
    assert (saved['exit_code'] == expected_code and saved['cleanup_confirmed']
            and saved['active_processes_at_end'] == 0), (label, saved)
    if expected_text is not None:
        assert expected_text.encode() in result.stdout, (label, result.stdout, result.stderr[:500])
    if expected_code == 0:
        assert not result.stderr, (label, 'unexpected stderr', result.stderr[:500])
    checks.append(label)


check('success', "Write-Output 'managed-integration'", expected_text='managed-integration')
check('native-failure', '& $env:ComSpec /d /c exit 7', expected_code=1)
check('write-error', "Write-Error 'expected-failure'", expected_code=1)
check('explicit-exit', 'exit 7', expected_code=7)
check('using-directive', 'using namespace System.Text\n[StringBuilder]::new().GetType().Name', expected_text='StringBuilder')
check('unicode', "[Console]::WriteLine('Привет-✓')", expected_text='Привет-✓')
check('cwd', '(Get-Location).Path', expected_text=CWD)
check('environment', '$env:AGENT_EXEC_TEST', expected_text='bounded-value')
check('large-source', '# ' + 'x' * 14000 + "\nWrite-Output 'large-tail'", expected_text='large-tail')
check('cmd', 'echo cmd-parity', expected_text='cmd-parity', shell='cmd')
check('bash', "printf 'bash-parity\\n'", expected_text='bash-parity', shell='bash')

canonical = command_line("Write-Output 'safe'", 'integration:gate')
for bad in ['Write-Output unsafe', canonical + '; echo escape', canonical + ' & echo escape',
            canonical + '\necho escape', canonical + ' extra', PORTABLE + ' run ' + 'a' * 32,
            PORTABLE + ' status; echo escape', canonical.replace('--timeout 10', '--timeout 99999')]:
    assert gate(bad)['hookSpecificOutput']['permissionDecision'] == 'deny', bad[:80]
    assert gate(bad, 'agy')['decision'] == 'deny', bad[:80]
checks.append('native-gates-deny-raw-compound-oversized')

# v2 is the AGY hook adapter; policy still selects v1 for actual execution.
assert json.loads((HOME / 'policy.json').read_text(encoding='utf-8-sig'))['execution']['binary_name'] == 'agent-exec.v1.exe'
assert gate(canonical, 'agy', ensure_ascii=False) == AGY_PASS
assert gate(canonical, 'agy', ensure_ascii=True) == AGY_PASS
wrong_target = canonical.replace(PORTABLE, AGY_GATE.replace('\\', '/'), 1)
assert gate(wrong_target, 'agy')['decision'] == 'deny'
assert gate(wrong_target)['hookSpecificOutput']['permissionDecision'] == 'deny'
checks.append('agy-v2-canonical-v1-target-and-utf8')

for suffix in ['status', 'maintain', 'cancel ' + 'a' * 32]:
    assert gate(PORTABLE + ' ' + suffix) == {}
    assert gate(PORTABLE + ' ' + suffix, 'agy') == AGY_PASS
checks.append('management-command-pass-shapes')

assert gate_payload({'tool_name': 'Read', 'tool_input': {}}, 'codex') == {}
assert gate_payload({'toolCall': {'name': 'view_file', 'args': {}}}, 'agy') == AGY_PASS
checks.append('irrelevant-tool-pass-shapes')

for payload in [b'{', b'{}', b'{"toolCall":{"name":"run_command"}}',
                b'{"toolCall":{"name":"run_command","args":{}}}']:
    result = invoke([AGY_GATE, 'hook', 'agy'], input=payload)
    assert result.returncode == 0 and not result.stderr, result.stderr
    denied = json.loads(result.stdout.decode('utf-8-sig'))
    assert denied['decision'] == 'deny' and denied['reason'], denied
checks.append('malformed-agy-hook-input-denied')

# Invalid identity fails at policy loading without changing canonical policy or data.
with tempfile.TemporaryDirectory(prefix='policy-name-', dir=HOME / 'tests') as temporary:
    fixture = pathlib.Path(temporary) / 'policy.json'
    original_policy = json.loads((HOME / 'policy.json').read_text(encoding='utf-8-sig'))
    for invalid_name in [None, 42, 'agent-exec.exe', '../agent-exec.v1.exe',
                         r'C:\other\agent-exec.v1.exe', 'agent-exec.v1.exe\n']:
        policy = json.loads(json.dumps(original_policy))
        if invalid_name is None:
            del policy['execution']['binary_name']
        else:
            policy['execution']['binary_name'] = invalid_name
        fixture.write_text(json.dumps(policy, ensure_ascii=False), encoding='utf-8')
        rejected = invoke([AGY_GATE, '--policy', str(fixture), 'status'])
        assert rejected.returncode == 125, (invalid_name, rejected.returncode)
        assert b'InvalidDataException' in rejected.stderr, (invalid_name, rejected.stderr[:300])
checks.append('policy-binary-name-required-and-validated')

readable_source = "Write-Output 'readable-Привет'"
readable = (f"{PORTABLE} inline --owner integration:readable --shell powershell --timeout 10 --command-base64 "
            "([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(@'\n" + readable_source + "\n'@)))")
assert gate(readable) == {} and gate(readable, 'agy') == AGY_PASS
shown = invoke([PS, '-NoProfile', '-NonInteractive', '-Command', readable])
assert shown.returncode == 0 and 'readable-Привет'.encode() in shown.stdout and not shown.stderr
readable_receipt = receipt('integration:readable')
assert readable_receipt['cleanup_confirmed'] and readable_receipt['active_processes_at_end'] == 0
for source in ["first\n'@))); Write-Output escape\n@'\nlast", "first\r'@))); Write-Output escape\nlast"]:
    unsafe = readable.replace(readable_source, source)
    assert gate(unsafe)['hookSpecificOutput']['permissionDecision'] == 'deny'
    assert gate(unsafe, 'agy')['decision'] == 'deny'
checks.append('readable-literal-and-terminator-escape-denial')

owner = 'integration:cancel'
command = command_line("Start-Sleep -Seconds 10; Write-Output 'should-not-finish'", owner)
child = subprocess.Popen([PS, '-NoProfile', '-NonInteractive', '-Command', command],
                         cwd=CWD, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
identifier = None
try:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        state = json.loads(invoke([EXE, 'status']).stdout)
        found = [item for item in state['active'] if item.get('Owner', item.get('owner')) == owner]
        if found:
            identifier = found[0].get('RunId', found[0].get('run_id'))
            break
        time.sleep(.05)
    assert identifier, 'cancel target not registered'
    assert invoke([EXE, 'cancel', identifier]).returncode == 0
    output, error = child.communicate(timeout=5)
    assert b'should-not-finish' not in output and child.returncode != 0
    saved = receipt(owner)
    assert (saved['reason'] == 'cancelled' and saved['cleanup_confirmed']
            and saved['active_processes_at_end'] == 0), saved
finally:
    if child.poll() is None and identifier:
        invoke([EXE, 'cancel', identifier])
        child.communicate(timeout=5)
checks.append('registered-cancel')

state = json.loads(invoke([EXE, 'status']).stdout)
assert state['pending'] == baseline_state['pending'], state
assert not any(str(item.get('Owner', item.get('owner', ''))).startswith('integration:') for item in state['active']), state
print(json.dumps({'status': 'PASS', 'execution_binary': EXE, 'codex_gate': CODEX_GATE,
                  'agy_gate': AGY_GATE, 'checks': checks, 'count': len(checks),
                  'pending_at_end': state['pending'], 'runtime_bytes': state['runtime_bytes']}, ensure_ascii=False))
