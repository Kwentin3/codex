using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace AgentExecution
{
    internal static class AgentExec
    {
        private static readonly string Home = AppDomain.CurrentDomain.BaseDirectory;
        private static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 262144 };

        public static int Main(string[] args)
        {
            try
            {
                // Scheduled maintenance has no console/stdin handle. Hook/command sessions do.
                try { Console.InputEncoding = new UTF8Encoding(false); } catch (IOException) { }
                try { Console.OutputEncoding = new UTF8Encoding(false); } catch (IOException) { }
                if (args.Length == 0) { Help(); return 0; }
                string policyPath = Path.Combine(Home, "policy.json");
                int pi = Array.IndexOf(args, "--policy");
                int commandSeparator = Array.IndexOf(args, "--");
                if (pi >= 0 && (commandSeparator < 0 || pi < commandSeparator))
                {
                    if (pi + 1 >= args.Length) throw new ArgumentException("policy path missing");
                    policyPath = Path.GetFullPath(args[pi + 1]);
                    args = args.Where((v, i) => i != pi && i != pi + 1).ToArray();
                }
                Policy policy = Policy.Load(policyPath);
                string action = args[0];
                if (action == "hook")
                {
                    if (!String.Equals(policyPath, Path.Combine(Home, "policy.json"), StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("hooks require the canonical shared policy");
                    return Hook(policy, args.Length > 1 ? args[1] : "");
                }
                if (action == "status") { WriteJson(RunStore.Status(policy)); return 0; }
                if (action == "maintain") { RunStore.Maintain(policy); return 0; }
                if (action == "cancel" && args.Length == 2)
                {
                    RunStore.RequestCancel(policy, args[1]);
                    WriteJson(new { run_id = args[1], cancellation_requested = true });
                    return 0;
                }
                if (action == "run" && args.Length >= 2)
                {
                    Request request = RunStore.ClaimRequest(policy, args[1]);
                    return RunClaimed(policy, request, Option(args, "--shell", null), policyPath);
                }
                if (action == "inline") return Inline(policy, args, policyPath);
                if (action == "exec") return Exec(policy, args, policyPath);
                throw new ArgumentException("unknown command");
            }
            catch (Exception error)
            {
                // Input/tool JSON and command text can contain credentials. Never echo either.
                if (args.Length > 1 && args[0] == "hook")
                    return Deny(args[1], "Agent execution control could not validate this request (" + error.GetType().Name + ").");
                Console.Error.WriteLine("agent-exec: rejected or failed (" + error.GetType().Name + ").");
                return 125;
            }
        }

        private static int Hook(Policy policy, string agent)
        {
            if (agent != "codex" && agent != "agy") throw new ArgumentException("unknown hook adapter");
            string input = ReadBounded(Console.In, 262144);
            Dictionary<string, object> body = Json.DeserializeObject(input) as Dictionary<string, object>;
            if (body == null) throw new ArgumentException("invalid hook input");
            string command;
            if (agent == "codex")
            {
                if (StringValue(body, "tool_name") != "Bash") return Pass(agent);
                Dictionary<string, object> tool = Map(body, "tool_input");
                command = StringValue(tool, "command");
            }
            else
            {
                Dictionary<string, object> call = Map(body, "toolCall");
                if (StringValue(call, "name") != "run_command") return Pass(agent);
                Dictionary<string, object> tool = Map(call, "args");
                command = StringValue(tool, "CommandLine");
            }
            string executable = Path.Combine(Home, policy.BinaryName).Replace('\\', '/');
            if (executable.Any(Char.IsWhiteSpace))
                throw new InvalidOperationException("portable hook path contains whitespace");
            string prefix = "^" + Regex.Escape(executable);
            if (Regex.IsMatch(command, prefix + @" (status|maintain|cancel [0-9a-f]{32})\z"))
            { return Pass(agent); }
            string header = prefix + @" inline --owner ([A-Za-z0-9_.:-]{1,96}) --shell (powershell|cmd|bash) --timeout ([0-9]{1,5}) --command-base64 ";
            Match allowed = Regex.Match(command, header + @"([A-Za-z0-9+/]+={0,2})\z");
            bool readable = false;
            if (!allowed.Success)
            {
                // This exact PowerShell expression only encodes a literal string. No workload
                // code is evaluated by the outer shell before it enters the Job owner.
                allowed = Regex.Match(command, header + @"\(\[Convert\]::ToBase64String\(\[Text.Encoding\]::UTF8.GetBytes\(@'\r?\n([\s\S]*)\r?\n'@\)\)\)\z");
                readable = allowed.Success;
            }
            if (allowed.Success)
            {
                int seconds = Int32.Parse(allowed.Groups[3].Value);
                if (readable)
                {
                    string source = allowed.Groups[4].Value;
                    if (source.Contains("'@")) return Deny(agent, "The literal contains a here-string terminator token. Use the exact base64 form.");
                    DecodePayload(Convert.ToBase64String(new UTF8Encoding(false, true).GetBytes(source)));
                }
                else DecodePayload(allowed.Groups[4].Value);
                if (seconds < 1 || seconds > policy.MaximumTimeoutSeconds)
                    return Deny(agent, "Requested command deadline exceeds the shared policy.");
                // A gate must never rewrite source or grant approval. The native client assesses
                // precisely the managed command its agent submitted, under its existing policy.
                return Pass(agent);
            }
            return Deny(agent, "Use the shared managed command route described in C:/Users/Администратор/.agents/windows-execution/README.md: " + executable + " inline --owner TASK --shell powershell --timeout SECONDS --command-base64 UTF8_BASE64. Submit one exact invocation with no shell operators; keep Cwd on the native tool.");
        }

        private static int Pass(string agent)
        {
            if (agent == "agy") WriteJson(new { decision = "allow" });
            else WriteJson(new { });
            return 0;
        }

        private static int Deny(string agent, string reason)
        {
            if (agent == "agy") WriteJson(new { decision = "deny", reason = reason });
            else WriteJson(new { hookSpecificOutput = new {
                hookEventName = "PreToolUse", permissionDecision = "deny", permissionDecisionReason = reason
            }});
            return 0;
        }

        private static string DecodePayload(string encoded)
        {
            if (encoded.Length > 22000 || !Regex.IsMatch(encoded, @"^[A-Za-z0-9+/]+={0,2}$"))
                throw new ArgumentException("command payload exceeds bound");
            byte[] bytes = Convert.FromBase64String(encoded);
            if (bytes.Length == 0 || bytes.Length > 16000) throw new ArgumentException("command source exceeds bound");
            string command = new UTF8Encoding(false, true).GetString(bytes);
            if (String.IsNullOrWhiteSpace(command) || command.IndexOf('\0') >= 0) throw new ArgumentException("invalid command source");
            return command;
        }

        private static int Inline(Policy policy, string[] args, string policyPath)
        {
            if (args.Length != 9 || args[1] != "--owner" || args[3] != "--shell" || args[5] != "--timeout" || args[7] != "--command-base64" ||
                !Regex.IsMatch(args[2], @"^[A-Za-z0-9_.:-]{1,96}$") || !Regex.IsMatch(args[4], @"^(powershell|cmd|bash)$"))
                throw new ArgumentException("noncanonical managed command");
            int seconds;
            if (!Int32.TryParse(args[6], out seconds) || seconds < 1 || seconds > policy.MaximumTimeoutSeconds)
                throw new ArgumentException("deadline outside policy");
            string command = DecodePayload(args[8]);
            Request request = new Request { RunId = Guid.NewGuid().ToString("N"), Agent = "managed", Owner = args[2],
                Command = command, Cwd = Environment.CurrentDirectory,
                Heavy = IsHeavy(command) || args[2].StartsWith("heavy:", StringComparison.Ordinal) || args[2].StartsWith("background:heavy:", StringComparison.Ordinal),
                Background = args[2].StartsWith("background:", StringComparison.Ordinal),
                TimeoutSeconds = seconds, CreatedUtcTicks = DateTime.UtcNow.Ticks };
            string id = RunStore.CreateRequest(policy, request);
            return RunClaimed(policy, RunStore.ClaimRequest(policy, id), args[4], policyPath);
        }

        private static int RunClaimed(Policy policy, Request request, string shell, string policyPath)
        {
            RunSpec spec;
            try
            {
                string script = RunStore.StageScript(policy, request.RunId, request.Command + "\nif (-not $?) { exit 1 }\n");
                spec = ShellCommand.Prepare(request.Command, request.Cwd, shell, script);
            }
            catch
            {
                RunStore.Complete(policy, request.RunId, new Dictionary<string, object> {
                    { "run_id", request.RunId }, { "status", "not_started" }, { "completed_utc_ticks", DateTime.UtcNow.Ticks }
                });
                throw;
            }
            return Execute(policy, request, spec, policyPath);
        }

        private static int Exec(Policy policy, string[] args, string policyPath)
        {
            int split = Array.IndexOf(args, "--");
            if (split < 0 || split + 1 >= args.Length) throw new ArgumentException("explicit executable required");
            string[] command = args.Skip(split + 1).ToArray();
            string program = Path.GetFullPath(command[0]);
            if (!Path.IsPathRooted(command[0]) || !File.Exists(program))
                throw new ArgumentException("executable must be an existing absolute path");
            int timeout;
            if (!Int32.TryParse(Option(args.Take(split).ToArray(), "--timeout", policy.TimeoutSeconds.ToString()), out timeout)
                || timeout < 1 || timeout > policy.MaximumTimeoutSeconds)
                throw new ArgumentException("timeout outside policy");
            Request request = new Request {
                RunId = Guid.NewGuid().ToString("N"), Agent = "explicit",
                Owner = Option(args.Take(split).ToArray(), "--owner", "explicit"),
                Command = String.Join(" ", command), Cwd = Environment.CurrentDirectory,
                Heavy = args.Take(split).Contains("--heavy"), Background = false,
                TimeoutSeconds = timeout, CreatedUtcTicks = DateTime.UtcNow.Ticks
            };
            string id = RunStore.CreateRequest(policy, request);
            request = RunStore.ClaimRequest(policy, id);
            RunSpec spec = new RunSpec { Executable = program,
                Arguments = String.Join(" ", command.Skip(1).Select(ShellCommand.QuoteWindows)),
                WorkingDirectory = request.Cwd };
            return Execute(policy, request, spec, policyPath);
        }

        private static int Execute(Policy policy, Request request, RunSpec spec, string policyPath)
        {
            Mutex heavy = null, slot = null;
            int ownerPid = Process.GetCurrentProcess().Id;
            long ownerStart = Process.GetCurrentProcess().StartTime.ToUniversalTime().Ticks;
            string jobName = "Global\\AgentExec-" + UserKey() + "-" + request.RunId;
            var receipt = new Dictionary<string, object> {
                { "run_id", request.RunId }, { "agent", request.Agent }, { "owner", request.Owner },
                { "job_name", jobName }, { "owner_pid", ownerPid }, { "owner_start_utc_ticks", ownerStart },
                { "started_utc_ticks", DateTime.UtcNow.Ticks }, { "timeout_seconds", request.TimeoutSeconds },
                { "heavy", request.Heavy }, { "background", request.Background },
                { "command_sha256", Hash(Encoding.UTF8.GetBytes(request.Command)) },
                { "policy_sha256", Hash(File.ReadAllBytes(policyPath)) },
                { "shell_executable", spec.Executable }, { "parent_pid", WinJob.GetParentProcessId() }
            };
            try
            {
                if (request.Heavy) heavy = Acquire("Heavy", policy.MaxConcurrentHeavyRuns, policy.QueueTimeoutSeconds);
                slot = Acquire("Slot", policy.MaxConcurrentRuns, policy.QueueTimeoutSeconds);
                // Reserve the worst case for the complete owned pool. Concurrent admissions
                // may read the same snapshot; all possible slots still fit behind this check.
                RequireCommit((ulong)policy.MemoryMb * (ulong)policy.MaxConcurrentRuns * 1048576UL +
                    (ulong)policy.CommitHeadroomMb * 1048576UL);
                RunStore.SetActive(policy, new ActiveRun {
                    RunId = request.RunId, Agent = request.Agent, Owner = request.Owner, JobName = jobName,
                    OwnerPid = ownerPid, OwnerStartUtcTicks = ownerStart, StartedUtcTicks = DateTime.UtcNow.Ticks
                });
                spec.MemoryBytes = (long)policy.MemoryMb * 1048576L;
                spec.MaxProcesses = policy.MaxProcesses;
                spec.TimeoutMilliseconds = checked(request.TimeoutSeconds * 1000);
                spec.MaxOutputBytes = policy.MaxOutputBytes;
                spec.JobName = jobName;
                spec.WatchParent = true;
                spec.ForwardStdin = true;
                spec.IsCancelled = delegate { return RunStore.IsCancelled(policy, request.RunId); };
                RunResult result = WinJob.Run(spec);
                receipt["process_id"] = result.ProcessId;
                receipt["exit_code"] = result.ExitCode;
                receipt["reason"] = result.Reason;
                receipt["cleanup_confirmed"] = result.CleanupConfirmed;
                receipt["output_clipped"] = result.OutputClipped;
                receipt["stdout_bytes"] = result.StdoutBytes;
                receipt["stderr_bytes"] = result.StderrBytes;
                receipt["peak_job_memory_bytes"] = result.PeakJobMemoryBytes;
                receipt["active_processes_at_end"] = result.ActiveProcessesAtEnd;
                receipt["status"] = result.CleanupConfirmed ? "finished" : "cleanup_unknown";
                return result.CleanupConfirmed ? result.ExitCode : 125;
            }
            catch (Exception error)
            {
                receipt["status"] = "rejected_or_failed";
                receipt["error_type"] = error.GetType().Name;
                Console.Error.WriteLine("agent-exec: run " + request.RunId + " failed (" + error.GetType().Name + ").");
                return 125;
            }
            finally
            {
                receipt["completed_utc_ticks"] = DateTime.UtcNow.Ticks;
                try { RunStore.Complete(policy, request.RunId, receipt); }
                finally
                {
                    if (slot != null) { slot.ReleaseMutex(); slot.Dispose(); }
                    if (heavy != null) { heavy.ReleaseMutex(); heavy.Dispose(); }
                }
            }
        }

        private static Mutex Acquire(string group, int count, int seconds)
        {
            Mutex[] choices = Enumerable.Range(0, count).Select(i => new Mutex(false,
                "Global\\AgentExec-Admission-v1-" + group + "-" + i)).ToArray();
            int index;
            try { index = WaitHandle.WaitAny(choices, TimeSpan.FromSeconds(seconds)); }
            catch (AbandonedMutexException abandoned) { index = abandoned.MutexIndex; }
            if (index == WaitHandle.WaitTimeout || index < 0 || index >= choices.Length)
            {
                foreach (Mutex choice in choices) choice.Dispose();
                throw new TimeoutException("admission queue expired");
            }
            for (int i = 0; i < choices.Length; i++) if (i != index) choices[i].Dispose();
            return choices[index];
        }

        private static bool IsHeavy(string command)
        {
            return Regex.IsMatch(command, @"(?im)^\s*#\s*agent-exec:\s*heavy\b") ||
                Regex.IsMatch(command, @"(?i)\b(pytest|msbuild|cmake)\b|\b(dotnet|cargo|go)\s+(build|test)\b|\bnpm\s+(run\s+)?build\b");
        }

        internal static string UserKey()
        {
            return Hash(Encoding.UTF8.GetBytes(WindowsIdentity.GetCurrent().User.Value)).Substring(0, 16);
        }
        internal static string Hash(byte[] value)
        { using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(value)).Replace("-", "").ToLowerInvariant(); }
        private static string Option(string[] args, string name, string fallback)
        { int i = Array.IndexOf(args, name); return i < 0 ? fallback : i + 1 < args.Length ? args[i + 1] : throwMissing(); }
        private static string throwMissing() { throw new ArgumentException("option value missing"); }
        private static string ReadBounded(TextReader reader, int maximum)
        {
            StringBuilder text = new StringBuilder(); char[] buffer = new char[4096]; int size;
            while ((size = reader.Read(buffer, 0, buffer.Length)) > 0)
            { if (text.Length + size > maximum) throw new ArgumentException("hook input too large"); text.Append(buffer, 0, size); }
            return text.ToString();
        }
        private static Dictionary<string, object> Map(Dictionary<string, object> source, string key)
        { object value; if (!source.TryGetValue(key, out value) || !(value is Dictionary<string, object>)) throw new ArgumentException("missing object"); return (Dictionary<string, object>)value; }
        private static string StringValue(Dictionary<string, object> source, string key)
        { object value; return source.TryGetValue(key, out value) && value != null ? Convert.ToString(value) : ""; }
        private static bool BoolValue(Dictionary<string, object> source, string key)
        { object value; return source.TryGetValue(key, out value) && value is bool && (bool)value; }
        private static void WriteJson(object value) { Console.WriteLine(Json.Serialize(value)); }
        private static void Help()
        { Console.WriteLine("Managed inline --owner TASK --shell powershell|cmd|bash --timeout SEC --command-base64 UTF8_BASE64; hook codex|agy; exec --owner TASK [--timeout SEC] [--heavy] -- ABSOLUTE_EXE ARGS; status; cancel ID; maintain. Policy: " + Path.Combine(Home, "policy.json")); }

        [StructLayout(LayoutKind.Sequential)] private class MemoryStatus
        {
            public uint Length = (uint)Marshal.SizeOf(typeof(MemoryStatus)); public uint Load;
            public ulong TotalPhysical, AvailablePhysical, TotalPageFile, AvailablePageFile, TotalVirtual, AvailableVirtual, AvailableExtendedVirtual;
        }
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GlobalMemoryStatusEx([In, Out] MemoryStatus status);
        private static void RequireCommit(ulong minimum)
        { MemoryStatus status = new MemoryStatus(); if (!GlobalMemoryStatusEx(status) || status.AvailablePageFile < minimum) throw new InvalidOperationException("insufficient commit reserve"); }
    }
}
