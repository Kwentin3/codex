using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using AgentExecution;

internal static class WinJobSmoke
{
    private static readonly string Self = Process.GetCurrentProcess().MainModule.FileName;
    private static string Quote(string value) { return "\"" + value + "\""; }
    private static int Main(string[] args)
    {
        try
        {
            if (args.Length > 0 && args[0] == "root") return Root(args[1], args[2]);
            if (args.Length > 0 && args[0] == "leaf")
            {
                WritePid(args[1]);
                Thread.Sleep(10000); return 0;
            }
            if (args.Length > 0 && args[0] == "owner") return Owner(args);
            if (args.Length > 0 && args[0] == "ephemeral-parent")
            {
                Process p = StartOwner("parent", args[1], args[2], args[3], true);
                WaitLines(args[1], 2, 3000);
                return 0;
            }
            string folder = args.Length > 1 && args[0] == "suite" ? args[1] : Path.Combine(Path.GetDirectoryName(Self), "winjob-smoke-" + DateTime.UtcNow.ToString("yyyyMMddTHHmmss") + "-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            string[] cases = args.Length > 0 && args[0] != "suite" ? args : new string[] { "normal", "timeout", "cancel", "output", "tail", "mixed", "nooutput", "zero", "tiny", "stdin", "process", "memory", "named", "collision", "ownerdeath", "parentdeath", "startuplimit", "cancelerror", "blockedoutput", "notice", "notice-open" };
            if (args.Length > 2 && args[0] == "suite") cases = new string[] { args[2] };
            foreach (string test in cases)
            {
                Stopwatch time = Stopwatch.StartNew();
                Test(test, folder);
                Console.Error.WriteLine("PASS|" + test + "|" + time.ElapsedMilliseconds + "ms");
            }
            Console.Error.WriteLine("EVIDENCE|" + folder);
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine("FAIL|" + e.GetType().Name + "|" + e.Message); return 1; }
    }

    private static RunSpec Spec(string mode, string pidFile, string name)
    {
        return new RunSpec {
            Executable = Self, Arguments = "root " + mode + " " + Quote(pidFile),
            WorkingDirectory = Path.GetDirectoryName(Self), JobName = name,
            MemoryBytes = 128L * 1024 * 1024, MaxProcesses = 8,
            TimeoutMilliseconds = 4000, MaxOutputBytes = 1024,
            WatchParent = false, ForwardStdin = true
        };
    }

    private static int Owner(string[] args)
    {
        string test = args[1], mode = "spawnsleep";
        if (test == "normal") mode = "spawnexit";
        if (test == "output" || test == "zero" || test == "tiny" || test == "blockedoutput") mode = "output";
        if (test == "tail" || test == "mixed") mode = test;
        if (test == "nooutput") mode = "simple";
        if (test == "stdin") mode = "stdin";
        if (test == "process") mode = "denied";
        if (test == "memory") mode = "memory";
        if (test == "startuplimit") mode = "simple";
        if (test == "notice" || test == "notice-open")
        {
            uint flags, outputSize, inputSize, instances;
            int noticeBytes = 64;
            uint capacity = 0;
            if (test == "notice")
            {
                Check(GetNamedPipeInfo(GetStdHandle(-12), out flags, out outputSize, out inputSize, out instances), "notice fixture pipe capacity unavailable");
                capacity = Math.Max(outputSize, inputSize);
                Check(capacity <= 65536, "notice fixture pipe is unexpectedly large");
                noticeBytes = Math.Max(4096, (int)capacity) + 1024;
            }
            Stopwatch noticeTime = Stopwatch.StartNew();
            bool first = WinJob.WriteNotice(test == "notice" ? new String('N', noticeBytes) : "NOTICE_ONE\n", noticeBytes);
            bool second = test == "notice" || WinJob.WriteNotice("NOTICE_TWO\n", 64);
            File.WriteAllText(args[3], "notice|" + noticeTime.ElapsedMilliseconds + "|" + first + "|" + second + "|" + noticeBytes + "|" + capacity, Encoding.UTF8);
            return 0;
        }

        RunSpec spec = Spec(mode, args[2], args[4]);
        spec.WatchParent = args[5] == "true";
        if (test == "timeout") spec.TimeoutMilliseconds = 700;
        if (test == "process") spec.MaxProcesses = 1;
        if (test == "memory") spec.MemoryBytes = 24L * 1024 * 1024;
        if (test == "startuplimit") spec.MemoryBytes = 4096;
        if (test == "tail" || test == "mixed") spec.MaxOutputBytes = 512;
        if (test == "zero") spec.MaxOutputBytes = 0;
        if (test == "tiny") spec.MaxOutputBytes = 1;
        if (test == "blockedoutput") spec.MaxOutputBytes = 16384;
        Stopwatch timer = Stopwatch.StartNew();
        int cancellationChecks = 0;
        long previousCheck = -1, minimumGap = Int64.MaxValue;
        if (test == "cancel") spec.IsCancelled = delegate() {
            long now = timer.ElapsedMilliseconds;
            cancellationChecks++;
            if (previousCheck >= 0) minimumGap = Math.Min(minimumGap, now - previousCheck);
            previousCheck = now;
            return now >= 700;
        };
        if (test == "cancelerror") spec.IsCancelled = delegate() { throw new InvalidOperationException("expected cancellation query failure"); };
        RunResult result = WinJob.Run(spec);
        if (test == "cancel") File.WriteAllText(args[3] + ".cancel",
            cancellationChecks + "|" + minimumGap + "|" + timer.ElapsedMilliseconds, Encoding.UTF8);

        File.WriteAllText(args[3], String.Join("|", new string[] {
            result.Reason, result.ExitCode.ToString(), result.CleanupConfirmed.ToString(), result.OutputClipped.ToString(),
            result.StdoutBytes.ToString(), result.StderrBytes.ToString(), result.PeakJobMemoryBytes.ToString(),
            result.ActiveProcessesAtEnd.ToString(), result.ProcessId.ToString()
        }), Encoding.UTF8);
        return 0;
    }

    private static int Root(string mode, string pidFile)
    {
        WritePid(pidFile);
        if (mode == "output")
        {
            byte[] bytes = new byte[8192];
            for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)'A';
            Console.OpenStandardOutput().Write(bytes, 0, bytes.Length);
            for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)'B';
            Console.OpenStandardError().Write(bytes, 0, bytes.Length);
            return 0;
        }
        if (mode == "tail" || mode == "mixed")
        {
            byte[] output = Encoding.ASCII.GetBytes("OUT_HEAD\n" + new String('A', mode == "tail" ? 8192 : 4096) + "\nOUT_TAIL\n");
            Console.OpenStandardOutput().Write(output, 0, output.Length);
            if (mode == "mixed")
            {
                byte[] error = Encoding.ASCII.GetBytes("ERR_HEAD\n" + new String('B', 4096) + "\nERR_TAIL\n");
                Console.OpenStandardError().Write(error, 0, error.Length);
            }
            return 0;
        }

        if (mode == "stdin")
        {
            byte[] bytes = new byte[128]; int count = 0, read;
            Stream input = Console.OpenStandardInput();
            while ((read = input.Read(bytes, count, bytes.Length - count)) != 0) { count += read; if (count == bytes.Length) return 82; }
            return Encoding.UTF8.GetString(bytes, 0, count) == "forwarded-input" ? 9 : 83;
        }
        if (mode == "memory")
        {
            IntPtr limits = Marshal.AllocHGlobal(144);
            try
            {
                if (!QueryInformationJobObject(IntPtr.Zero, 9, limits, 144, IntPtr.Zero)) return 86;
                File.WriteAllText(pidFile + ".memory", "limit=" + Marshal.ReadInt64(limits, 120) + "|flags=" + Marshal.ReadInt32(limits, 16));
                for (int i = 0; i < 48; i++)
                {
                    IntPtr chunk = VirtualAlloc(IntPtr.Zero, new UIntPtr(1024 * 1024), 0x3000, 4);
                    if (chunk == IntPtr.Zero)
                    {
                        File.AppendAllText(pidFile + ".memory", "|refused=" + Marshal.GetLastWin32Error() + "|successfulMiB=" + i);
                        return 79;
                    }
                }
                return 84;
            }
            finally { Marshal.FreeHGlobal(limits); }
        }
        if (mode == "simple") return 7;
        try
        {
            Process.Start(new ProcessStartInfo(Self, "leaf " + Quote(pidFile)) { UseShellExecute = false, CreateNoWindow = true });
            if (mode == "denied") return 78;
        }
        catch (System.ComponentModel.Win32Exception) { if (mode == "denied") return 77; throw; }
        WaitLines(pidFile, 2, 1500);
        if (mode == "spawnexit") return 7;
        Thread.Sleep(10000);
        return 0;
    }

    private static Process StartOwner(string test, string pidFile, string receipt, string name, bool watchParent)
    {
        Process owner = Process.Start(new ProcessStartInfo(Self, "owner " + test + " " + Quote(pidFile) + " " + Quote(receipt) + " " + Quote(name) + " " + watchParent.ToString().ToLowerInvariant()) {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        });
        IntPtr original = owner.Handle;
        File.WriteAllText(pidFile + ".owner", owner.Id + "|" + owner.StartTime.ToUniversalTime().ToFileTimeUtc());
        return owner;
    }

    private sealed class Drain
    {
        private Thread thread;
        private readonly MemoryStream retained = new MemoryStream(32768);
        public long Bytes;
        public Drain(Stream stream)
        {
            thread = new Thread(delegate() {
                try
                {
                    byte[] b = new byte[4096]; int n;
                    while ((n = stream.Read(b, 0, b.Length)) > 0)
                    {
                        Interlocked.Add(ref Bytes, n);
                        int keep = Math.Min(n, 32768 - (int)retained.Length);
                        if (keep > 0) retained.Write(b, 0, keep);
                    }
                }
                catch (IOException) { }
            });
            thread.IsBackground = true; thread.Start();
        }
        public void Finish() { if (!thread.Join(1000)) throw new Exception("smoke output reader did not stop"); }
        public string Text { get { return Encoding.UTF8.GetString(retained.ToArray()); } }
    }


    private static void Test(string test, string folder)
    {
        string file = Path.Combine(folder, test + ".pids"), receipt = Path.Combine(folder, test + ".receipt");
        string name = "Global\\AgentExec-smoke-" + Guid.NewGuid().ToString("N");
        File.WriteAllText(Path.Combine(folder, test + ".job"), name);
        Process owner = null, intermediary = null;
        Drain output = null, error = null;
        List<IntPtr> participants = new List<IntPtr>();
        try
        {
            if (test == "blockedoutput")
            {
                owner = StartOwner(test, file, receipt, name, false);
                Check(owner.WaitForExit(6500), "blocked final output prevented owner completion");
                output = new Drain(owner.StandardOutput.BaseStream);
                error = new Drain(owner.StandardError.BaseStream);
                output.Finish(); error.Finish();
                WaitFile(receipt, 1000);
                string[] blocked = File.ReadAllText(receipt, Encoding.UTF8).Split('|');
                Check(owner.ExitCode == 0 && blocked.Length == 9 && blocked[0] == "exited" &&
                    blocked[1] == "0" && blocked[2] == "True" && blocked[3] == "True" && blocked[7] == "0",
                    "blocked final output did not stop and reap workers: " + String.Join("|", blocked));
                Check(output.Bytes + error.Bytes <= 16384 && WinJob.GetActiveProcesses(name) == null,
                    "blocked output exceeded cap or retained its job");
                Console.Error.WriteLine("BLOCKED_OUTPUT|" + String.Join("|", blocked) + "|emitted=" + (output.Bytes + error.Bytes));
                return;
            }
            if (test == "notice" || test == "notice-open")
            {
                owner = StartOwner(test, file, receipt, name, false);
                if (test == "notice")
                {
                    // Deliberately leave stderr undrained until the helper has
                    // returned; the write is larger than the native pipe capacity.
                    Check(owner.WaitForExit(1500), "notice blocked owner completion");
                    output = new Drain(owner.StandardOutput.BaseStream);
                    error = new Drain(owner.StandardError.BaseStream);
                }
                else
                {
                    output = new Drain(owner.StandardOutput.BaseStream);
                    error = new Drain(owner.StandardError.BaseStream);
                    Check(owner.WaitForExit(1500), "short notices did not finish");
                }
                output.Finish(); error.Finish();
                WaitFile(receipt, 1000);
                string[] notice = File.ReadAllText(receipt, Encoding.UTF8).Split('|');
                Check(owner.ExitCode == 0 && notice.Length == 6 && notice[0] == "notice", "notice fixture failed");
                Check(Int64.Parse(notice[1]) < 500, "notice exceeded bounded attempt: " + notice[1]);
                if (test == "notice")
                {
                    Check(notice[2] == "False", "undrained pipe did not exercise a blocked notice");
                    Check(error.Bytes <= Int32.Parse(notice[4]) && output.Bytes == 0, "notice output exceeded its allowance");
                }
                else Check(notice[2] == "True" && notice[3] == "True" && error.Text == "NOTICE_ONE\nNOTICE_TWO\n", "notice closed or changed stderr");
                Console.Error.WriteLine("NOTICE|" + test + "|" + String.Join("|", notice) + "|emitted=" + error.Bytes);
                return;
            }

            if (test == "parentdeath")
            {
                intermediary = Process.Start(new ProcessStartInfo(Self, "ephemeral-parent " + Quote(file) + " " + Quote(receipt) + " " + Quote(name)) {
                    UseShellExecute = false, CreateNoWindow = true
                });
                WaitLines(file, 2, 4000);
                CaptureParticipants(file, participants);
                Check(intermediary.WaitForExit(4000), "intermediate parent did not exit");
                WaitFile(receipt, 4000);
            }
            else
            {
                owner = StartOwner(test == "ownerdeath" || test == "named" || test == "collision" ? "long" : test, file, receipt, name, false);
                output = new Drain(owner.StandardOutput.BaseStream); error = new Drain(owner.StandardError.BaseStream);
                if (test == "stdin") { owner.StandardInput.Write("forwarded-input"); owner.StandardInput.Close(); }
                if (test == "ownerdeath" || test == "named" || test == "collision")
                {
                    WaitLines(file, 2, 3000);
                    CaptureParticipants(file, participants);
                    Check(WinJob.GetActiveProcesses(name) >= 2, "named job did not contain root and grandchild");
                    if (test == "collision")
                    {
                        RunSpec duplicate = Spec("simple", file + ".duplicate", name);
                        duplicate.ForwardStdin = false;
                        RunResult rejected = WinJob.Run(duplicate);
                        Check(rejected.ProcessId == 0 && rejected.Reason == "job_setup_failed_win32_183" && rejected.CleanupConfirmed, "named collision was not rejected safely: " + rejected.Reason);
                        Check(WinJob.GetActiveProcesses(name) >= 2, "collision touched existing job");
                    }
                    if (test == "ownerdeath")
                    {
                        IntPtr originalOwner = owner.Handle;
                        Check(TerminateProcess(originalOwner, 91), "could not stop owned smoke owner");
                    }
                    else Check(WinJob.TerminateNamed(name, 130), "named cancellation did not find owned job");
                }
                Check(owner.WaitForExit(7000), "owner exceeded bounded smoke wait");
                output.Finish(); error.Finish();

                if (test != "ownerdeath") WaitFile(receipt, 1000);
            }
            if (participants.Count == 0 && File.Exists(file)) CaptureParticipants(file, participants);
            foreach (IntPtr handle in participants) Check(WaitForSingleObject(handle, 3000) == 0, "owned participant survived owner completion");
            Check(WinJob.GetActiveProcesses(name) == null, "named job survived owner completion");
            Check(!WinJob.TerminateNamed(name, 130), "missing job cancel should return false");
            if (test == "ownerdeath")
            {
                Check(!File.Exists(receipt), "force-killed owner unexpectedly wrote completion receipt");
                return;
            }
            string[] r = File.ReadAllText(receipt, Encoding.UTF8).Split('|');
            Check(r.Length == 9 && r[2] == "True" && r[7] == "0", "cleanup receipt failed: " + String.Join("|", r));
            if (test == "normal") Check(r[0] == "exited" && r[1] == "7", "normal root exit not preserved");
            if (test == "timeout") Check(r[0] == "timeout" && r[1] == "124", "timeout receipt wrong");
            if (test == "cancel")
            {
                Check(r[0] == "cancelled" && r[1] == "130", "cancel receipt wrong");
                string[] timing = File.ReadAllText(receipt + ".cancel", Encoding.UTF8).Split('|');
                Check(Int32.Parse(timing[0]) >= 2 && Int32.Parse(timing[0]) <= 4 && Int64.Parse(timing[1]) >= 400 && Int64.Parse(timing[2]) < 2000, "cancellation lookup cadence or response changed: " + String.Join("|", timing));
                Console.Error.WriteLine("CANCEL|" + String.Join("|", timing));
            }
            if (test == "cancelerror") Check(r[0] == "cancellation_check_failed" && r[1] == "125", "cancellation errors were hidden");
            if (test == "parentdeath") Check(r[0] == "parent_exit", "original parent death not detected: " + r[0]);
            if (test == "stdin") Check(r[0] == "exited" && r[1] == "9", "stdin did not forward and close");
            if (test == "output") Check(r[0] == "exited" && r[1] == "0" && r[3] == "True" && Int64.Parse(r[4]) + Int64.Parse(r[5]) == 16384, "output accounting wrong");
            if (test == "process") Check((r[0] == "active_process_limit" || r[1] == "77") && File.ReadAllLines(file).Length == 1, "process cap did not block spawn");
            if (test == "memory")
            {
                string native = File.ReadAllText(file + ".memory");
                // The Server2019 peak counter exceeded the configured cap in
                // this probe; exact OS accounting cause remains unverified.
                // Assert native budget and observed allocation refusal, retaining
                // the unmodified peak rather than clamping it to the budget.
                Check((r[0] == "job_memory_limit" || r[1] == "79") && native.StartsWith("limit=25165824|flags=8712"), "small job memory cap not enforced: " + String.Join("|", r) + "|" + native);
                Console.Error.WriteLine("MEMORY|" + native + "|reportedPeak=" + r[6]);
            }
            if (test == "startuplimit") Check(r[0] == "job_memory_limit" && !File.Exists(file) && r[8] != "0", "startup limit did not stop the process before user code");
            CheckOutput(test, output, error, r);
            Console.Error.WriteLine("RECEIPT|" + test + "|" + String.Join("|", r));
        }
        finally
        {
            WinJob.TerminateNamed(name, 125);
            if (owner != null)
            {
                if (!owner.HasExited) { TerminateProcess(owner.Handle, 125); owner.WaitForExit(2000); }
                owner.Dispose();
            }
            if (intermediary != null)
            {
                if (!intermediary.HasExited) { TerminateProcess(intermediary.Handle, 125); intermediary.WaitForExit(2000); }
                intermediary.Dispose();
            }
            foreach (IntPtr handle in participants)
            {
                if (WaitForSingleObject(handle, 0) != 0) { TerminateProcess(handle, 125); WaitForSingleObject(handle, 2000); }
                CloseHandle(handle);
            }
        }
    }

    private static void CheckOutput(string test, Drain output, Drain error, string[] receipt)
    {
        if (test != "output" && test != "tail" && test != "mixed" && test != "zero" && test != "tiny" && test != "nooutput") return;
        long emitted = output.Bytes + error.Bytes;
        if (test == "nooutput")
        {
            Check(emitted == 0 && receipt[3] == "False" && receipt[4] == "0" && receipt[5] == "0", "no-output behavior changed");
            return;
        }
        int cap = test == "output" ? 1024 : test == "zero" ? 0 : test == "tiny" ? 1 : 512;
        Check(emitted == cap && receipt[3] == "True", "combined output allowance wrong: " + emitted + "/" + cap);
        if (test == "zero") return;
        if (test == "tiny")
        {
            Check(output.Bytes == 0 && error.Text == "!", "tiny allowance did not retain a clipping indicator");
            return;
        }
        System.Text.RegularExpressions.Match marker = System.Text.RegularExpressions.Regex.Match(error.Text,
            @"\n\[agent-exec: output clipped; omitted by limit=([0-9]+) bytes; observed=([0-9]+) bytes\]\n");
        Check(marker.Success, "visible clipping/count notice absent");
        long observed = Int64.Parse(receipt[4]) + Int64.Parse(receipt[5]);
        long kept = emitted - Encoding.ASCII.GetByteCount(marker.Value);
        Check(Int64.Parse(marker.Groups[1].Value) == observed - kept && Int64.Parse(marker.Groups[2].Value) == observed, "clipping byte counts differ from emitted data");
        if (test == "output")
        {
            Check(receipt[4] == "8192" && receipt[5] == "8192", "raw stream counts changed");
            Check(output.Text.Trim('A').Length == 0 && error.Text.Replace(marker.Value, "").Trim('B').Length == 0, "child bytes crossed stdout/stderr");
        }
        if (test == "tail")
        {
            Check(receipt[4] == "8211" && receipt[5] == "0", "long stdout accounting changed");
            Check(output.Text.StartsWith("OUT_HEAD\n") && output.Text.EndsWith("\nOUT_TAIL\n") && error.Text == marker.Value, "head or final stdout evidence lost");
        }
        if (test == "mixed")
        {
            Check(receipt[4] == "4115" && receipt[5] == "4115", "mixed stream accounting changed");
            Check(output.Text.EndsWith("\nOUT_TAIL\n") && error.Text.EndsWith("\nERR_TAIL\n"), "both stream tails were not retained");
            Check(!output.Text.Contains("ERR_TAIL") && !error.Text.Contains("OUT_TAIL"), "retained tails changed streams");
        }
    }


    private static void CaptureParticipants(string file, List<IntPtr> handles)
    {
        foreach (string line in File.ReadAllLines(file))
        {
            string[] fields = line.Trim('\uFEFF', '\r', '\n', ' ').Split('|');
            uint id;
            ulong expectedCreated;
            if (fields.Length != 2 || !UInt32.TryParse(fields[0], out id) || !UInt64.TryParse(fields[1], out expectedCreated)) throw new Exception("bad participant identity receipt");
            IntPtr handle = OpenProcess(0x101001, false, id);
            if (handle == IntPtr.Zero) continue;
            ulong created, exit, kernel, user;
            if (!GetProcessTimes(handle, out created, out exit, out kernel, out user)) { CloseHandle(handle); throw new Exception("participant identity query failed"); }
            if (created != expectedCreated) { CloseHandle(handle); continue; }
            handles.Add(handle);
        }
    }
    private static void WritePid(string file)
    {
        Process current = Process.GetCurrentProcess();
        File.AppendAllText(file, current.Id + "|" + current.StartTime.ToUniversalTime().ToFileTimeUtc() + Environment.NewLine, Encoding.UTF8);
    }
    private static void WaitLines(string file, int count, int milliseconds)
    {
        Stopwatch wait = Stopwatch.StartNew();
        while (wait.ElapsedMilliseconds < milliseconds)
        {
            try { if (File.Exists(file) && File.ReadAllLines(file).Length >= count) return; } catch (IOException) { }
            Thread.Sleep(10);
        }
        throw new Exception("smoke participant readiness timeout");
    }
    private static void WaitFile(string file, int milliseconds)
    {
        Stopwatch wait = Stopwatch.StartNew();
        while (!File.Exists(file) && wait.ElapsedMilliseconds < milliseconds) Thread.Sleep(10);
        Check(File.Exists(file), "smoke receipt missing");
    }
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr GetStdHandle(int kind);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeInfo(IntPtr pipe, out uint flags, out uint outputSize, out uint inputSize, out uint instances);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, uint id);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(IntPtr process, out ulong created, out ulong exit, out ulong kernel, out ulong user);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr bytes, uint allocation, uint protection);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length, IntPtr returned);
}
