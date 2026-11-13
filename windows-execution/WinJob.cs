using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace AgentExecution
{
    public sealed class RunSpec
    {
        public string Executable, Arguments, WorkingDirectory, JobName;
        public long MemoryBytes;
        public int MaxProcesses, TimeoutMilliseconds, MaxOutputBytes;
        public bool WatchParent = true, ForwardStdin = true;
        public Func<bool> IsCancelled;
    }

    public sealed class RunResult
    {
        public uint ProcessId;
        public int ExitCode;
        public string Reason;
        public bool CleanupConfirmed, OutputClipped;
        public long StdoutBytes, StderrBytes, PeakJobMemoryBytes;
        public int ActiveProcessesAtEnd;
    }

    // A single command owner. The job handle is never inherited: its last close
    // kills descendants even when the owner itself is terminated abruptly.
    public static class WinJob
    {
        private const uint KillOnClose = 0x2000, JobMemory = 0x200, ActiveProcessLimit = 8;
        private const uint Synchronize = 0x100000, QueryLimited = 0x1000;
        private const uint Suspended = 4, UnicodeEnvironment = 0x400;
        private const uint ExtendedStartup = 0x80000, NoWindow = 0x08000000;
        private const uint WaitObject = 0, WaitTimeout = 258;
        private static readonly IntPtr InvalidHandle = new IntPtr(-1);

        public static bool WriteNotice(string text, int maxBytes)
        {
            if (maxBytes < 0) throw new ArgumentOutOfRangeException("maxBytes");
            if (String.IsNullOrEmpty(text) || maxBytes == 0) return true;
            int count = Math.Min(text.Length, maxBytes);
            byte[] bytes = new byte[count];
            Encoding.ASCII.GetBytes(text, 0, count, bytes, 0);
            return Worker.Notice(bytes);
        }


        public static RunResult Run(RunSpec input)
        {
            if (input == null) throw new ArgumentNullException("input");
            RunSpec spec = new RunSpec {
                Executable = input.Executable, Arguments = input.Arguments,
                WorkingDirectory = input.WorkingDirectory, JobName = input.JobName, MemoryBytes = input.MemoryBytes,
                MaxProcesses = input.MaxProcesses, TimeoutMilliseconds = input.TimeoutMilliseconds,
                MaxOutputBytes = input.MaxOutputBytes, WatchParent = input.WatchParent,
                ForwardStdin = input.ForwardStdin, IsCancelled = input.IsCancelled
            };
            Validate(spec);
            RunResult result = new RunResult { ExitCode = 125, Reason = "not_started", ActiveProcessesAtEnd = -1 };
            IntPtr job = IntPtr.Zero, port = IntPtr.Zero;
            ProcessInfo child = new ProcessInfo();
            Pipes pipes = new Pipes();
            ParentWatch parent = null;
            Capture capture = null;
            Worker stdout = null, stderr = null, stdin = null;
            bool assigned = false, handlerAttached = false;
            int interrupted = 0;
            long nextCancellationCheck = 0;
            string phase = "setup_failed";
            Stopwatch duration = Stopwatch.StartNew();
            ConsoleCancelEventHandler onCancel = delegate(object sender, ConsoleCancelEventArgs e) {
                e.Cancel = true;
                Interlocked.Exchange(ref interrupted, 1);
            };
            try
            {
                Console.CancelKeyPress += onCancel;
                handlerAttached = true;
                phase = "watch_parent_failed";
                if (spec.WatchParent) parent = new ParentWatch();
                if (parent != null && !parent.IsAlive) { result.Reason = "parent_exit"; return result; }
                phase = "job_setup_failed";
                job = CreateJobObject(IntPtr.Zero, String.IsNullOrEmpty(spec.JobName) ? null : spec.JobName);
                int createJobError = Marshal.GetLastWin32Error();
                CheckHandle(job);
                if (createJobError == 183)
                {
                    Close(ref job);
                    throw new Win32Exception(createJobError);
                }
                ExtendedLimits limits = new ExtendedLimits();
                limits.BasicLimitInformation.LimitFlags = KillOnClose | JobMemory | ActiveProcessLimit;
                limits.BasicLimitInformation.ActiveProcessLimit = (uint)spec.MaxProcesses;
                limits.JobMemoryLimit = new UIntPtr((ulong)spec.MemoryBytes);
                SetJob(job, 9, limits);
                port = CreateIoCompletionPort(InvalidHandle, IntPtr.Zero, UIntPtr.Zero, 1);
                CheckHandle(port);
                SetJob(job, 7, new CompletionPort { CompletionKey = new IntPtr(1), Port = port });
                phase = "pipes_failed";
                pipes.Create();
                capture = new Capture(spec.MaxOutputBytes);
                phase = "create_failed";
                using (Startup startup = new Startup(pipes))
                {
                    StringBuilder command = new StringBuilder("\"" + spec.Executable + "\"" +
                        (String.IsNullOrEmpty(spec.Arguments) ? "" : " " + spec.Arguments));
                    if (!CreateProcess(spec.Executable, command, IntPtr.Zero, IntPtr.Zero, true,
                        Suspended | UnicodeEnvironment | ExtendedStartup | NoWindow,
                        IntPtr.Zero, String.IsNullOrEmpty(spec.WorkingDirectory) ? null : spec.WorkingDirectory,
                        ref startup.Info, out child)) ThrowNative();
                }
                result.ProcessId = child.ProcessId;
                // No instruction in the child can execute before this assignment.
                phase = "assign_failed";
                if (!AssignProcessToJobObject(job, child.Process)) ThrowNative();
                assigned = true;
                pipes.CloseChildEnds();
                stdout = Worker.ReadOutput(pipes.OutRead, capture, false);
                stderr = Worker.ReadOutput(pipes.ErrRead, capture, true);
                if (spec.ForwardStdin)
                {
                    IntPtr inputWrite = pipes.InWrite;
                    pipes.InWrite = IntPtr.Zero;
                    stdin = Worker.ForwardInput(inputWrite);
                }
                else Close(ref pipes.InWrite);
                phase = "cancellation_check_failed";
                string stop = StopReason(spec, parent, duration, ref interrupted, ref nextCancellationCheck);
                if (stop != null) { result.Reason = stop; result.ExitCode = ReasonExitCode(stop); return result; }
                phase = "resume_failed";
                if (ResumeThread(child.Thread) == UInt32.MaxValue) ThrowNative();
                Close(ref child.Thread);
                phase = "monitor_failed";
                while (true)
                {
                    stop = ReadLimitNotice(port);
                    if (stop == null)
                    {
                        phase = "cancellation_check_failed";
                        stop = StopReason(spec, parent, duration, ref interrupted, ref nextCancellationCheck);
                        phase = "monitor_failed";
                    }
                    if (stop != null)
                    {
                        result.Reason = stop;
                        result.ExitCode = ReasonExitCode(stop);
                        break;
                    }
                    uint wait = WaitForSingleObject(child.Process, 25);
                    if (wait == WaitObject)
                    {
                        // A process can fail an allocation/spawn and exit before
                        // the next polling iteration. Keep queued limit evidence.
                        stop = ReadLimitNotice(port);
                        uint exit;
                        if (!GetExitCodeProcess(child.Process, out exit)) ThrowNative();
                        result.Reason = stop ?? "exited";
                        result.ExitCode = stop == null ? unchecked((int)exit) : ReasonExitCode(stop);
                        break;
                    }
                    if (wait != WaitTimeout) ThrowNative();
                }
            }
            catch (Win32Exception e)
            {
                result.Reason = phase + "_win32_" + e.NativeErrorCode;
                result.ExitCode = 125;
            }
            catch (Exception)
            {
                // Do not put command text, environment or exception payloads in
                // the receipt. The caller can log the bounded status category.
                result.Reason = phase;
                result.ExitCode = 125;
            }
            finally
            {
                if (handlerAttached) Console.CancelKeyPress -= onCancel;
                pipes.CloseChildEnds();
                bool rootStopped = child.Process == IntPtr.Zero;
                bool empty = job == IntPtr.Zero;
                if (child.Process != IntPtr.Zero)
                {
                    // Also reap on an ordinary root exit: a successful shell
                    // exit never transfers ownership of leftover descendants.
                    if (assigned) TerminateJobObject(job, unchecked((uint)result.ExitCode));
                    else TerminateProcess(child.Process, unchecked((uint)result.ExitCode));
                    rootStopped = WaitForSingleObject(child.Process, 3000) == WaitObject;
                }
                if (job != IntPtr.Zero)
                {
                    Stopwatch reap = Stopwatch.StartNew();
                    do
                    {
                        int active;
                        if (!TryActiveProcesses(job, out active)) break;
                        result.ActiveProcessesAtEnd = active;
                        if (active == 0) { empty = true; break; }
                        Thread.Sleep(20);
                    } while (reap.ElapsedMilliseconds < 3000);
                    ExtendedLimits finalLimits;
                    if (TryQueryJob(job, 9, out finalLimits))
                        result.PeakJobMemoryBytes = unchecked((long)finalLimits.PeakJobMemoryUsed.ToUInt64());
                }
                else result.ActiveProcessesAtEnd = 0;
                // stdin may never reach EOF (an interactive parent). Cancel its
                // blocked read without closing or changing the parent's input.
                if (stdin != null) stdin.Cancel();
                bool ioStopped = FinishWorkers(capture, stdout, stderr, stdin);
                if (capture != null)
                {
                    if (!capture.Completed) capture.MarkClipped();
                    result.StdoutBytes = Interlocked.Read(ref capture.StdoutBytes);
                    result.StderrBytes = Interlocked.Read(ref capture.StderrBytes);
                    result.OutputClipped = capture.Clipped || !ioStopped;
                }
                result.CleanupConfirmed = rootStopped && empty && ioStopped;
                // Mark workers stopped before their owned pipe handles close.
                pipes.Dispose();
                Close(ref child.Thread);
                Close(ref child.Process);
                // KILL_ON_JOB_CLOSE remains the last-resort owner-death guard,
                // while a successful receipt requires the earlier active=0 query.
                Close(ref job);
                Close(ref port);
                if (parent != null) parent.Dispose();
            }
            return result;
        }

        private static void Validate(RunSpec spec)
        {
            if (String.IsNullOrWhiteSpace(spec.Executable) || !Path.IsPathRooted(spec.Executable) ||
                spec.Executable.IndexOf('"') >= 0 || spec.Executable.IndexOf('\0') >= 0 || !File.Exists(spec.Executable))
                throw new ArgumentException("Executable must be an existing absolute executable path.");
            if (spec.Arguments != null && (spec.Arguments.IndexOf('\0') >= 0 || spec.Arguments.Length + spec.Executable.Length > 32760))
                throw new ArgumentException("Invalid or excessive arguments.");
            if (!String.IsNullOrEmpty(spec.WorkingDirectory) && !Directory.Exists(spec.WorkingDirectory))
                throw new ArgumentException("WorkingDirectory does not exist.");
            if (spec.MemoryBytes <= 0 || (IntPtr.Size == 4 && spec.MemoryBytes > UInt32.MaxValue) ||
                spec.MaxProcesses <= 0 || spec.TimeoutMilliseconds <= 0 || spec.MaxOutputBytes < 0)
                throw new ArgumentException("Positive memory, process and time budgets and a nonnegative output cap are required.");
            if (!String.IsNullOrEmpty(spec.JobName)) ValidateJobName(spec.JobName);
        }

        private static string StopReason(RunSpec spec, ParentWatch parent, Stopwatch duration,
            ref int interrupted, ref long nextCancellationCheck)
        {
            if (Interlocked.CompareExchange(ref interrupted, 0, 0) != 0) return "ctrl_c";
            if (parent != null && !parent.IsAlive) return "parent_exit";
            long now = duration.ElapsedMilliseconds;
            if (spec.IsCancelled != null && now >= nextCancellationCheck)
            {
                nextCancellationCheck = now + 500;
                if (spec.IsCancelled()) return "cancelled";
            }
            if (duration.ElapsedMilliseconds >= spec.TimeoutMilliseconds) return "timeout";
            return null;
        }

        private static int ReasonExitCode(string reason)
        {
            if (reason == "timeout") return 124;
            if (reason == "cancelled" || reason == "ctrl_c") return 130;
            if (reason == "job_memory_limit") return 137;
            return 125;
        }

        private static string ReadLimitNotice(IntPtr port)
        {
            string reason = null;
            for (int i = 0; i < 64; i++)
            {
                uint message;
                UIntPtr key;
                IntPtr data;
                if (!GetQueuedCompletionStatus(port, out message, out key, out data, 0))
                {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 258) break;
                    throw new Win32Exception(error);
                }
                if (key.ToUInt64() != 1) continue;
                if (message == 9 || message == 10) reason = "job_memory_limit";
                else if (message == 3 && reason == null) reason = "active_process_limit";
            }
            return reason;
        }

        private static bool FinishWorkers(Capture capture, params Worker[] workers)
        {
            Stopwatch wait = Stopwatch.StartNew();
            foreach (Worker worker in workers)
            {
                if (worker == null) continue;
                int remaining = Math.Max(0, 4000 - (int)wait.ElapsedMilliseconds);
                worker.Join(remaining);
            }
            for (int i = 0; i < workers.Length; i++)
            {
                Worker worker = workers[i];
                if (worker == null) continue;
                if (i < 2 && worker.IsAlive && capture != null) capture.MarkClipped();
                worker.Cancel();
            }
            bool finished = true;
            foreach (Worker worker in workers)
            {
                if (worker == null) continue;
                int remaining = Math.Max(0, 5000 - (int)wait.ElapsedMilliseconds);
                if (!worker.Join(remaining)) finished = false;
            }
            return finished;
        }

        public static int GetParentProcessId() { return GetParentProcessId(Process.GetCurrentProcess().Id); }

        public static int GetParentProcessId(int processId)
        {
            IntPtr process = OpenProcess(QueryLimited, false, (uint)processId);
            if (process == IntPtr.Zero) return 0;
            try
            {
                ProcessBasicInfo info;
                int returned;
                int status = NtQueryInformationProcess(process, 0, out info, Marshal.SizeOf(typeof(ProcessBasicInfo)), out returned);
                return status < 0 ? 0 : unchecked((int)info.ParentId.ToInt64());
            }
            finally { Close(ref process); }
        }

        public static string QueryProcessExecutable(int processId)
        {
            IntPtr process = OpenProcess(QueryLimited, false, (uint)processId);
            if (process == IntPtr.Zero) return null;
            try
            {
                StringBuilder path = new StringBuilder(32768);
                int length = path.Capacity;
                return QueryFullProcessImageName(process, 0, path, ref length) ? path.ToString() : null;
            }
            finally { Close(ref process); }
        }

        public static int? GetActiveProcesses(string jobName)
        {
            ValidateJobName(jobName);
            IntPtr job = OpenJobObject(4, false, jobName);
            if (job == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 2) return null;
                throw new Win32Exception(error);
            }
            try
            {
                int active;
                if (!TryActiveProcesses(job, out active)) ThrowNative();
                return active;
            }
            finally { Close(ref job); }
        }

        public static bool TerminateNamed(string jobName, uint exitCode)
        {
            ValidateJobName(jobName);
            IntPtr job = OpenJobObject(8, false, jobName);
            if (job == IntPtr.Zero)
            {
                int error = Marshal.GetLastWin32Error();
                if (error == 2) return false;
                throw new Win32Exception(error);
            }
            try
            {
                if (!TerminateJobObject(job, exitCode)) ThrowNative();
                return true;
            }
            finally { Close(ref job); }
        }

        private static void ValidateJobName(string name)
        {
            const string prefix = "Global\\AgentExec-";
            if (String.IsNullOrEmpty(name) || !name.StartsWith(prefix, StringComparison.Ordinal) ||
                name.Length <= prefix.Length || name.Length > 240)
                throw new ArgumentException("JobName must be a unique Global\\AgentExec- name.");
            for (int i = prefix.Length; i < name.Length; i++)
            {
                char c = name[i];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'))
                    throw new ArgumentException("JobName suffix must contain only ASCII letters, digits and hyphens.");
            }
        }

        private sealed class ParentWatch : IDisposable
        {
            private IntPtr handle;
            public ParentWatch()
            {
                int id = GetParentProcessId();
                if (id <= 0) throw new Win32Exception(87);
                handle = OpenProcess(Synchronize | QueryLimited, false, (uint)id);
                CheckHandle(handle);
                FileTime parentCreated, ownerCreated, exit, kernel, user;
                if (!GetProcessTimes(handle, out parentCreated, out exit, out kernel, out user) ||
                    !GetProcessTimes(GetCurrentProcess(), out ownerCreated, out exit, out kernel, out user))
                {
                    int error = Marshal.GetLastWin32Error();
                    Dispose();
                    throw new Win32Exception(error);
                }
                if (parentCreated.Value > ownerCreated.Value)
                {
                    // Parent PID has been recycled. Never follow the new process.
                    Dispose();
                }
            }
            public bool IsAlive { get { return handle != IntPtr.Zero && WaitForSingleObject(handle, 0) == WaitTimeout; } }
            public void Dispose() { Close(ref handle); }
        }

        private sealed class Capture
        {
            private readonly int limit, headLimit;
            private readonly object gate = new object();
            private readonly Tail stdoutTail, stderrTail;
            private readonly Stream stdout = Console.OpenStandardOutput();
            private readonly Stream stderr = Console.OpenStandardError();
            private int headBytes, clipped, readersFinished, completed, stdoutFailed, stderrFailed;
            public long StdoutBytes, StderrBytes;

            public Capture(int maxBytes)
            {
                limit = maxBytes;
                headLimit = Math.Min(16384, maxBytes / 4);
                // Each stream has a bounded tail; the final shared allowance is
                // divided between them, borrowing unused space from the other.
                stdoutTail = new Tail(maxBytes - headLimit);
                stderrTail = new Tail(maxBytes - headLimit);
            }
            public bool Clipped { get { return Interlocked.CompareExchange(ref clipped, 0, 0) != 0; } }
            public bool Completed { get { return Interlocked.CompareExchange(ref completed, 0, 0) != 0; } }
            public void MarkClipped() { Interlocked.Exchange(ref clipped, 1); }

            public void Publish(byte[] bytes, int count, bool error, Worker owner)
            {
                if (error) Interlocked.Add(ref StderrBytes, count);
                else Interlocked.Add(ref StdoutBytes, count);
                int head;
                lock (gate)
                {
                    head = Math.Min(count, headLimit - headBytes);
                    headBytes += head;
                    (error ? stderrTail : stdoutTail).Append(bytes, head, count - head);
                    if (Interlocked.Read(ref StdoutBytes) + Interlocked.Read(ref StderrBytes) > limit) MarkClipped();
                }
                // Never hold the buffer lock while writing to a possibly full
                // outer pipe: its own worker remains cancellable.
                Write(bytes, 0, head, error, owner);
            }

            public void CompleteReader(Worker owner)
            {
                if (Interlocked.Increment(ref readersFinished) != 2) return;
                // Both readers have finished publishing. Flush from this last
                // retained worker, so blocked final writes can still be cancelled.
                try { Flush(owner); }
                finally { Interlocked.Exchange(ref completed, 1); }
            }

            private void Flush(Worker owner)
            {
                long total = Interlocked.Read(ref StdoutBytes) + Interlocked.Read(ref StderrBytes);
                if (!Clipped)
                {
                    WriteTail(stdoutTail, stdoutTail.Count, false, owner);
                    WriteTail(stderrTail, stderrTail.Count, true, owner);
                    return;
                }
                int available = limit - headBytes;
                int style = 0;
                byte[] marker = new byte[0];
                if (available > 0)
                {
                    // Choose a form using the largest possible omission count,
                    // then keep that form while its digit count settles.
                    while (style < 3 && Marker(style, total - headBytes, total).Length > available) style++;
                    marker = Encoding.ASCII.GetBytes(Marker(style, total - headBytes, total));
                }
                int output = 0, error = 0;
                for (int i = 0; i < 24; i++)
                {
                    DivideTail(Math.Max(0, available - marker.Length), out output, out error);
                    byte[] adjusted = available == 0 ? marker :
                        Encoding.ASCII.GetBytes(Marker(style, total - headBytes - output - error, total));
                    bool settled = adjusted.Length == marker.Length;
                    marker = adjusted;
                    if (settled) break;
                }
                // The control notice is stderr; retained child bytes always
                // remain on their original stdout/stderr channel.
                Write(marker, 0, marker.Length, true, owner);
                WriteTail(stdoutTail, output, false, owner);
                WriteTail(stderrTail, error, true, owner);
            }

            private void DivideTail(int available, out int output, out int error)
            {
                output = Math.Min(stdoutTail.Count, (available + 1) / 2);
                error = Math.Min(stderrTail.Count, available / 2);
                int spare = available - output - error;
                int more = Math.Min(stdoutTail.Count - output, spare);
                output += more; spare -= more;
                error += Math.Min(stderrTail.Count - error, spare);
            }

            private static string Marker(int style, long omitted, long observed)
            {
                string drop = omitted.ToString(System.Globalization.CultureInfo.InvariantCulture);
                string total = observed.ToString(System.Globalization.CultureInfo.InvariantCulture);
                if (style == 0) return "\n[agent-exec: output clipped; omitted by limit=" + drop + " bytes; observed=" + total + " bytes]\n";
                if (style == 1) return "[clipped " + drop + " of " + total + " bytes]\n";
                if (style == 2) return "!" + total;
                // A zero cap emits nothing. Smaller nonzero caps cannot contain
                // a complete count, but still show clipping; receipts keep totals.
                return "!";
            }

            private void WriteTail(Tail tail, int count, bool error, Worker owner)
            {
                if (count == 0) return;
                int start = (tail.Start + tail.Count - count) % tail.Bytes.Length;
                int first = Math.Min(count, tail.Bytes.Length - start);
                Write(tail.Bytes, start, first, error, owner);
                Write(tail.Bytes, 0, count - first, error, owner);
            }

            private void Write(byte[] bytes, int offset, int count, bool error, Worker owner)
            {
                if (count == 0) return;
                if (owner.IsStopping) { MarkClipped(); return; }
                int failed = error ? Interlocked.CompareExchange(ref stderrFailed, 0, 0) :
                    Interlocked.CompareExchange(ref stdoutFailed, 0, 0);
                if (failed != 0) return;
                try { (error ? stderr : stdout).Write(bytes, offset, count); }
                catch (Exception)
                {
                    if (error) Interlocked.Exchange(ref stderrFailed, 1);
                    else Interlocked.Exchange(ref stdoutFailed, 1);
                    MarkClipped();
                }
            }

            private sealed class Tail
            {
                public readonly byte[] Bytes;
                public int Start, Count;
                public Tail(int capacity) { Bytes = new byte[capacity]; }
                public void Append(byte[] source, int offset, int count)
                {
                    if (count == 0 || Bytes.Length == 0) return;
                    if (count >= Bytes.Length)
                    {
                        Buffer.BlockCopy(source, offset + count - Bytes.Length, Bytes, 0, Bytes.Length);
                        Start = 0; Count = Bytes.Length; return;
                    }
                    int drop = Math.Max(0, Count + count - Bytes.Length);
                    Start = (Start + drop) % Bytes.Length;
                    Count -= drop;
                    int index = (Start + Count) % Bytes.Length;
                    int first = Math.Min(count, Bytes.Length - index);
                    Buffer.BlockCopy(source, offset, Bytes, index, first);
                    Buffer.BlockCopy(source, offset + first, Bytes, 0, count - first);
                    Count += count;
                }
            }
        }


        private sealed class Worker
        {
            private Thread thread;
            private volatile bool stopping;
            private IntPtr nativeHandle;
            private readonly object nativeHandleLock = new object();
            private int initialized, initializationError;
            private Worker() { }
            private void Start(ThreadStart action, int startupTimeoutMilliseconds = 1000)
            {
                thread = new Thread(delegate() {
                    IntPtr retained;
                    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), out retained, 0, false, 2))
                    {
                        initializationError = Marshal.GetLastWin32Error();
                        Interlocked.Exchange(ref initialized, 1);
                        return;
                    }
                    lock (nativeHandleLock) nativeHandle = retained;
                    Interlocked.Exchange(ref initialized, 1);
                    try { if (!stopping) action(); }
                    finally { lock (nativeHandleLock) Close(ref nativeHandle); }
                });
                thread.IsBackground = true;
                thread.Start();
                Stopwatch wait = Stopwatch.StartNew();
                while (Interlocked.CompareExchange(ref initialized, 0, 0) == 0)
                {
                    if (wait.ElapsedMilliseconds >= startupTimeoutMilliseconds) { Cancel(); throw new Win32Exception(1460); }
                    Thread.Sleep(1);
                }
                if (initializationError != 0) throw new Win32Exception(initializationError);
            }
            public static bool Notice(byte[] bytes)
            {
                Worker worker = new Worker();
                Stopwatch wait = Stopwatch.StartNew();
                int written = 0;
                bool stopped = false;
                try
                {
                    worker.Start(delegate() {
                        try
                        {
                            // Do not close the process standard stream: another
                            // bounded executor notice may follow this one.
                            Console.OpenStandardError().Write(bytes, 0, bytes.Length);
                            Interlocked.Exchange(ref written, 1);
                        }
                        catch (Exception) { }
                    }, 50);
                    stopped = worker.Join(Math.Max(0, 200 - (int)wait.ElapsedMilliseconds));
                }
                catch (Exception)
                {
                    // This helper owns only its fixed control notice. Failure
                    // to publish it must not block native cleanup or receipts.
                }
                finally
                {
                    if (worker.thread != null && worker.thread.IsAlive)
                    {
                        worker.Cancel();
                        stopped = worker.Join(Math.Max(0, 250 - (int)wait.ElapsedMilliseconds));
                    }
                    else stopped = true;
                }
                return stopped && Interlocked.CompareExchange(ref written, 0, 0) != 0;
            }


            public static Worker ReadOutput(IntPtr source, Capture capture, bool error)
            {
                Worker worker = new Worker();
                worker.Start(delegate() {
                    byte[] bytes = new byte[16384];
                    try
                    {
                        while (!worker.stopping)
                        {
                            uint read;
                            if (!ReadFile(source, bytes, (uint)bytes.Length, out read, IntPtr.Zero))
                            {
                                int code = Marshal.GetLastWin32Error();
                                if (code != 109 && code != 232 && code != 995) capture.MarkClipped();
                                break;
                            }
                            if (read == 0) break;
                            capture.Publish(bytes, (int)read, error, worker);
                        }
                    }
                    finally { capture.CompleteReader(worker); }
                });
                return worker;
            }

            public static Worker ForwardInput(IntPtr destination)
            {
                Worker worker = new Worker();
                try { worker.Start(delegate() {
                    byte[] bytes = new byte[4096];
                    IntPtr source = GetStdHandle(-10);
                    try
                    {
                        while (!worker.stopping && source != IntPtr.Zero && source != InvalidHandle)
                        {
                            uint read;
                            if (!ReadFile(source, bytes, (uint)bytes.Length, out read, IntPtr.Zero) || read == 0) break;
                            int offset = 0;
                            while (offset < read && !worker.stopping)
                            {
                                // Keep the write buffer stable for the synchronous API.
                                byte[] chunk = bytes;
                                if (offset != 0)
                                {
                                    chunk = new byte[read - offset];
                                    Buffer.BlockCopy(bytes, offset, chunk, 0, chunk.Length);
                                }
                                uint written;
                                if (!WriteFile(destination, chunk, read - (uint)offset, out written, IntPtr.Zero) || written == 0) return;
                                offset += (int)written;
                            }
                        }
                    }
                    catch (Exception) { }
                    finally { CloseHandle(destination); }
                }); }
                catch { CloseHandle(destination); throw; }
                return worker;
            }
            public void Cancel()
            {
                stopping = true;
                // Retain the actual thread object; an integer thread ID can be
                // recycled between observing completion and issuing cancellation.
                lock (nativeHandleLock)
                    if (nativeHandle != IntPtr.Zero) CancelSynchronousIo(nativeHandle);
            }
            public bool IsStopping { get { return stopping; } }
            public bool IsAlive { get { return thread.IsAlive; } }
            public bool Join(int milliseconds) { return thread.Join(milliseconds); }
        }

        private sealed class Pipes : IDisposable
        {
            public IntPtr InRead, InWrite, OutRead, OutWrite, ErrRead, ErrWrite;
            public void Create()
            {
                SecurityAttributes attributes = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)), InheritHandle = true };
                if (!CreatePipe(out InRead, out InWrite, ref attributes, 0) ||
                    !SetHandleInformation(InWrite, 1, 0) ||
                    !CreatePipe(out OutRead, out OutWrite, ref attributes, 0) ||
                    !SetHandleInformation(OutRead, 1, 0) ||
                    !CreatePipe(out ErrRead, out ErrWrite, ref attributes, 0) ||
                    !SetHandleInformation(ErrRead, 1, 0)) ThrowNative();
            }
            public void CloseChildEnds() { Close(ref InRead); Close(ref OutWrite); Close(ref ErrWrite); }
            public void Dispose()
            {
                CloseChildEnds(); Close(ref InWrite); Close(ref OutRead); Close(ref ErrRead);
            }
        }

        private sealed class Startup : IDisposable
        {
            public StartupInfoEx Info;
            private IntPtr handles;
            private bool initialized;
            public Startup(Pipes pipes)
            {
                Info.StartupInfo.Size = Marshal.SizeOf(typeof(StartupInfoEx));
                Info.StartupInfo.Flags = 0x101;
                Info.StartupInfo.StdInput = pipes.InRead;
                Info.StartupInfo.StdOutput = pipes.OutWrite;
                Info.StartupInfo.StdError = pipes.ErrWrite;
                IntPtr bytes = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
                Info.AttributeList = Marshal.AllocHGlobal(bytes);
                try
                {
                    if (!InitializeProcThreadAttributeList(Info.AttributeList, 1, 0, ref bytes)) ThrowNative();
                    initialized = true;
                    handles = Marshal.AllocHGlobal(3 * IntPtr.Size);
                    Marshal.WriteIntPtr(handles, 0, pipes.InRead);
                    Marshal.WriteIntPtr(handles, IntPtr.Size, pipes.OutWrite);
                    Marshal.WriteIntPtr(handles, 2 * IntPtr.Size, pipes.ErrWrite);
                    if (!UpdateProcThreadAttribute(Info.AttributeList, 0, new IntPtr(0x20002), handles,
                        new IntPtr(3 * IntPtr.Size), IntPtr.Zero, IntPtr.Zero)) ThrowNative();
                }
                catch { Dispose(); throw; }
            }
            public void Dispose()
            {
                if (Info.AttributeList != IntPtr.Zero)
                {
                    if (initialized) DeleteProcThreadAttributeList(Info.AttributeList);
                    Marshal.FreeHGlobal(Info.AttributeList);
                    Info.AttributeList = IntPtr.Zero;
                }
                if (handles != IntPtr.Zero) { Marshal.FreeHGlobal(handles); handles = IntPtr.Zero; }
            }
        }

        private static void CheckHandle(IntPtr handle) { if (handle == IntPtr.Zero || handle == InvalidHandle) ThrowNative(); }
        private static void ThrowNative() { throw new Win32Exception(Marshal.GetLastWin32Error()); }
        private static void Close(ref IntPtr handle)
        {
            IntPtr old = handle;
            handle = IntPtr.Zero;
            if (old != IntPtr.Zero && old != InvalidHandle) CloseHandle(old);
        }
        private static void SetJob<T>(IntPtr job, int infoClass, T info) where T : struct
        {
            int length = Marshal.SizeOf(typeof(T));
            IntPtr data = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(info, data, false);
                if (!SetInformationJobObject(job, infoClass, data, (uint)length)) ThrowNative();
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        private static bool TryQueryJob<T>(IntPtr job, int infoClass, out T info) where T : struct
        {
            int length = Marshal.SizeOf(typeof(T));
            IntPtr data = Marshal.AllocHGlobal(length);
            try
            {
                if (!QueryInformationJobObject(job, infoClass, data, (uint)length, IntPtr.Zero)) { info = default(T); return false; }
                info = (T)Marshal.PtrToStructure(data, typeof(T));
                return true;
            }
            finally { Marshal.FreeHGlobal(data); }
        }
        private static bool TryActiveProcesses(IntPtr job, out int active)
        {
            Accounting info;
            bool ok = TryQueryJob(job, 1, out info);
            active = ok ? (int)info.ActiveProcesses : -1;
            return ok;
        }

        [StructLayout(LayoutKind.Sequential)] private struct FileTime { public uint Low, High; public ulong Value { get { return ((ulong)High << 32) | Low; } } }
        [StructLayout(LayoutKind.Sequential)] private struct ProcessBasicInfo { public IntPtr Reserved1, Peb, Reserved2a, Reserved2b, ProcessId, ParentId; }
        [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle; }
        [StructLayout(LayoutKind.Sequential)] private struct ProcessInfo { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StartupInfo { public int Size; public string Reserved, Desktop, Title; public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags; public short ShowWindow, Reserved2Size; public IntPtr Reserved2, StdInput, StdOutput, StdError; }
        [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { public StartupInfo StartupInfo; public IntPtr AttributeList; }
        [StructLayout(LayoutKind.Sequential)] private struct BasicLimits { public long PerProcessUserTime, PerJobUserTime; public uint LimitFlags; public UIntPtr MinWorkingSet, MaxWorkingSet; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
        [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
        [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits { public BasicLimits BasicLimitInformation; public IoCounters IoInfo; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
        [StructLayout(LayoutKind.Sequential)] private struct CompletionPort { public IntPtr CompletionKey, Port; }
        [StructLayout(LayoutKind.Sequential)] private struct Accounting { public long TotalUserTime, TotalKernelTime, ThisUserTime, ThisKernelTime; public uint PageFaultCount, TotalProcesses, ActiveProcesses, TerminatedProcesses; }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern IntPtr OpenJobObject(uint access, bool inheritHandle, string name);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length, IntPtr returned);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateIoCompletionPort(IntPtr file, IntPtr existingPort, UIntPtr key, uint threads);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetQueuedCompletionStatus(IntPtr port, out uint bytes, out UIntPtr key, out IntPtr overlapped, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessW")] private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory, ref StartupInfoEx startup, out ProcessInfo process);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(IntPtr process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(IntPtr process, out FileTime created, out FileTime exit, out FileTime kernel, out FileTime user);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder path, ref int length);
        [DllImport("ntdll.dll")] private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, out ProcessBasicInfo info, int length, out int returned);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SecurityAttributes attributes, uint size);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool ReadFile(IntPtr file, byte[] buffer, uint length, out uint read, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool WriteFile(IntPtr file, byte[] buffer, uint length, out uint written, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr GetStdHandle(int kind);
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentThread();
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source, IntPtr targetProcess, out IntPtr target, uint access, bool inherit, uint options);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CancelSynchronousIo(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returnedSize);
        [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    }
}
