using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace AgentExecution
{
    public sealed class Policy
    {
        internal const long MaximumRuntimeBytes = 32L * 1024 * 1024;
        public string DataRoot { get; private set; }
        public string BinaryName { get; private set; }
        public string StorageOwnerSid { get; private set; }
        public int MemoryMb { get; private set; }
        public int MaxProcesses { get; private set; }
        public int TimeoutSeconds { get; private set; }
        public int MaximumTimeoutSeconds { get; private set; }
        public int MaxOutputBytes { get; private set; }
        public int MaxConcurrentRuns { get; private set; }
        public int MaxConcurrentHeavyRuns { get; private set; }
        public int QueueTimeoutSeconds { get; private set; }
        public int CommitHeadroomMb { get; private set; }
        public long RuntimeMaxBytes { get; private set; }
        public int OrdinaryDays { get; private set; }

        public static Policy Load(string path)
        {
            RunStore.CheckPath(path, false);
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > 65536) throw new InvalidDataException("Policy is absent or oversized.");
            var json = new JavaScriptSerializer { MaxJsonLength = 65536, RecursionLimit = 16 };
            var root = json.DeserializeObject(File.ReadAllText(path, Encoding.UTF8)) as Dictionary<string, object>;
            if (root == null || Number(root, "schema_version", 1, 1) != 1) throw new InvalidDataException("Unsupported policy schema.");
            var retention = Section(root, "retention");
            var execution = Section(root, "execution");
            object storageOwner;
            if (!root.TryGetValue("storage_owner_sid", out storageOwner) || !(storageOwner is string))
                throw new InvalidDataException("Explicit storage_owner_sid is required.");
            string ownerSid = ParseStorageOwnerSid((string)storageOwner).Value;
            object binaryName;
            if (!execution.TryGetValue("binary_name", out binaryName) || !(binaryName is string) ||
                !System.Text.RegularExpressions.Regex.IsMatch((string)binaryName, @"\Aagent-exec\.v[0-9]+\.exe\z"))
                throw new InvalidDataException("execution.binary_name must be a versioned agent-exec filename.");
            long total = Number(retention, "total_bytes", 1, 512L * 1024 * 1024);
            long active = Number(retention, "active_reserved_bytes", 1, total);
            long closed = Number(retention, "closed_max_bytes", 1, total);
            long runtime = Number(retention, "runtime_max_bytes", 1, MaximumRuntimeBytes);
            long margin = Number(retention, "margin_bytes", 1, total);
            if (active + closed + runtime + margin > total) throw new InvalidDataException("Policy partitions exceed total budget.");
            Number(retention, "incident_days", 1, 30);
            object dataRoot;
            if (!root.TryGetValue("data_root", out dataRoot) || !(dataRoot is string)) throw new InvalidDataException("Missing data_root.");
            string dataPath = NormalizeDataRoot((string)dataRoot);
            var policy = new Policy {
                DataRoot = dataPath, BinaryName = (string)binaryName, StorageOwnerSid = ownerSid, RuntimeMaxBytes = runtime,
                OrdinaryDays = (int)Number(retention, "ordinary_days", 1, 7),
                MemoryMb = (int)Number(execution, "default_memory_mb", 1, 1048576),
                MaxProcesses = (int)Number(execution, "max_processes", 1, 1024),
                TimeoutSeconds = (int)Number(execution, "default_timeout_seconds", 1, 86400),
                MaximumTimeoutSeconds = (int)Number(execution, "maximum_timeout_seconds", 1, 86400),
                MaxOutputBytes = (int)Number(execution, "max_output_bytes", 1, 4194304),
                MaxConcurrentRuns = (int)Number(execution, "max_concurrent_runs", 1, 32),
                MaxConcurrentHeavyRuns = (int)Number(execution, "max_concurrent_heavy_runs", 1, 32),
                QueueTimeoutSeconds = (int)Number(execution, "queue_timeout_seconds", 1, 300),
                CommitHeadroomMb = (int)Number(execution, "commit_headroom_mb", 1, 1048576)
            };
            if (policy.TimeoutSeconds > policy.MaximumTimeoutSeconds || policy.MaxConcurrentHeavyRuns > policy.MaxConcurrentRuns)
                throw new InvalidDataException("Inconsistent execution bounds.");
            return policy;
        }

        internal static string NormalizeDataRoot(string dataPath)
        {
            if (String.IsNullOrWhiteSpace(dataPath) || !Path.IsPathRooted(dataPath) || dataPath.StartsWith("\\", StringComparison.Ordinal) ||
                !Path.GetPathRoot(dataPath).EndsWith("\\", StringComparison.Ordinal))
                throw new InvalidDataException("data_root must be a local absolute directory.");
            dataPath = Path.GetFullPath(dataPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (dataPath.Length <= 3 || String.Equals(dataPath, Path.GetPathRoot(dataPath).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("data_root cannot be a volume root.");
            RunStore.CheckPath(dataPath, true);
            return dataPath;
        }

        internal static SecurityIdentifier ParseStorageOwnerSid(string value)
        {
            SecurityIdentifier sid;
            try { sid = new SecurityIdentifier(value); }
            catch (ArgumentException) { throw new InvalidDataException("Invalid native storage_owner_sid."); }
            if (sid.Value != value) throw new InvalidDataException("storage_owner_sid must be canonical.");
            return sid;
        }

        private static Dictionary<string, object> Section(Dictionary<string, object> root, string key)
        {
            object value;
            if (!root.TryGetValue(key, out value) || !(value is Dictionary<string, object>)) throw new InvalidDataException("Missing policy section: " + key);
            return (Dictionary<string, object>)value;
        }

        private static long Number(Dictionary<string, object> root, string key, long min, long max)
        {
            object value;
            if (!root.TryGetValue(key, out value) || !(value is int || value is long)) throw new InvalidDataException("Missing integer policy value: " + key);
            long number = Convert.ToInt64(value, CultureInfo.InvariantCulture);
            if (number < min || number > max) throw new InvalidDataException("Policy bound invalid: " + key);
            return number;
        }
    }

    public sealed class Request
    {
        public string RunId, Agent, Owner, Command, Cwd;
        public bool Heavy, Background;
        public int TimeoutSeconds;
        public long CreatedUtcTicks;
    }

    public sealed class ActiveRun
    {
        public string RunId, Agent, Owner, JobName;
        public int OwnerPid;
        public long OwnerStartUtcTicks, StartedUtcTicks;
    }

    // One native security contract for Store, admission and telemetry mutexes.
    // Existing objects are opened without changing their ownership or ACL.
    public static class SharedMutex
    {
        public static Mutex Open(string name, string ownerSid)
        {
            if (name == null || !System.Text.RegularExpressions.Regex.IsMatch(name, @"\AGlobal\\AgentExec[A-Za-z0-9_-]{0,160}\z"))
                throw new ArgumentException("Mutex must belong to the bounded AgentExec namespace.", "name");
            SecurityIdentifier owner = Policy.ParseStorageOwnerSid(ownerSid);
            var security = new MutexSecurity();
            security.SetAccessRuleProtection(true, false);
            foreach (string sid in new[] { "S-1-5-18", "S-1-5-32-544", owner.Value }.Distinct(StringComparer.Ordinal))
                security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(sid), MutexRights.FullControl, AccessControlType.Allow));
            bool created;
            return new Mutex(false, name, out created, security);
        }
    }

    public static class RunStore
    {
        private const int RequestLimit = 65536, ActiveLimit = 4096, RecordLimit = 8192;
        private const int ReceiptFileLimit = 512 * 1024, ReceiptFiles = 8, PendingLimit = 32, ActiveFiles = 32;
        // Three request artifacts per pending ID, active records, receipt ring,
        // one atomic-write temp, plus one pending batch for bounded recovery.
        private const int InventoryLimit = PendingLimit * 3 + ActiveFiles + ReceiptFiles + 1 + PendingLimit;
        private static readonly Encoding Utf8 = new UTF8Encoding(false, true);
        private static readonly string MutexName = BuildMutexName();
        private static readonly HashSet<string> ReceiptKeys = new HashSet<string>(new[] {
            "run_id", "agent", "owner", "job_name", "owner_pid", "owner_start_utc_ticks", "started_utc_ticks", "completed_utc_ticks",
            "process_id", "exit_code", "reason", "cleanup_confirmed", "output_clipped", "stdout_bytes", "stderr_bytes",
            "peak_job_memory_bytes", "active_processes_at_end", "status", "timeout_seconds", "heavy", "background", "error_type",
            "command_sha256", "shell_executable", "parent_pid", "parent_start_utc_ticks", "policy_sha256"
        }, StringComparer.Ordinal);

        private sealed class Claim { public string RunId; public long CreatedUtcTicks; }
        private sealed class Layout
        {
            public string Root, Requests, Active, Receipts;
            public List<FileInfo> Files;
            public long Bytes;
        }
        private sealed class Gate : IDisposable
        {
            private readonly Mutex mutex;
            private bool held;
            public Gate(Policy policy) : this(StoreOwner(policy)) { }
            public Gate(string ownerSid)
            {
                mutex = SharedMutex.Open(MutexName, ownerSid);
                try { held = mutex.WaitOne(TimeSpan.FromSeconds(10)); }
                catch (AbandonedMutexException) { held = true; }
                if (!held) { mutex.Dispose(); throw new IOException("Runtime store is busy."); }
            }
            public void Dispose() { if (held) { held = false; mutex.ReleaseMutex(); } mutex.Dispose(); }
        }

        public static string CreateRequest(Policy policy, Request request)
        {
            if (request == null) throw new ArgumentNullException("request");
            using (new Gate(policy))
            {
                Layout layout = Prepare(policy, true);
                if (PendingIds(layout).Count >= PendingLimit) throw new IOException("Pending request quota reached.");
                request.RunId = Guid.NewGuid().ToString("N");
                request.CreatedUtcTicks = DateTime.UtcNow.Ticks;
                ValidateRequest(policy, request);
                byte[] bytes = Serialize(request, RequestLimit);
                AtomicWrite(policy, layout, Path.Combine(layout.Requests, request.RunId + ".json"), bytes);
                return request.RunId;
            }
        }

        public static Request ClaimRequest(Policy policy, string id)
        {
            ValidateId(id);
            using (new Gate(policy))
            {
                Layout layout = Prepare(policy);
                string file = Path.Combine(layout.Requests, id + ".json");
                string claimed = Path.Combine(layout.Requests, id + ".claimed");
                if (File.Exists(claimed)) throw new IOException("Request was already claimed.");
                Request request = Read<Request>(file, RequestLimit);
                ValidateRequest(policy, request);
                if (request.RunId != id || request.CreatedUtcTicks < DateTime.UtcNow.AddHours(-1).Ticks)
                    throw new InvalidDataException("Request identity or age invalid.");
                AtomicWrite(policy, layout, claimed, Serialize(new Claim { RunId = id, CreatedUtcTicks = request.CreatedUtcTicks }, 1024));
                try { SafeDelete(file); }
                catch { SafeDelete(claimed); throw; }
                return request;
            }
        }

        public static void SetActive(Policy policy, ActiveRun run)
        {
            ValidateActive(run);
            using (new Gate(policy))
            {
                Layout layout = Prepare(policy);
                if (!File.Exists(Path.Combine(layout.Requests, run.RunId + ".claimed"))) throw new IOException("Active run requires a claimed request.");
                string path = Path.Combine(layout.Active, run.RunId + ".json");
                if (File.Exists(path)) throw new IOException("Active ownership already exists.");
                if (FilesIn(layout, layout.Active).Count >= ActiveFiles) throw new IOException("Active state quota reached.");
                AtomicWrite(policy, layout, path, Serialize(run, ActiveLimit));
            }
        }

        public static string StageScript(Policy policy, string runId, string content)
        {
            ValidateId(runId);
            if (content == null || content.IndexOf('\0') >= 0) throw new InvalidDataException("Invalid script content.");
            byte[] text = Utf8.GetBytes(content);
            if (text.Length > RequestLimit - 3) throw new InvalidDataException("Staged script exceeds 64 KiB.");
            byte[] bytes = new byte[text.Length + 3];
            bytes[0] = 0xef; bytes[1] = 0xbb; bytes[2] = 0xbf;
            Buffer.BlockCopy(text, 0, bytes, 3, text.Length);
            using (new Gate(policy))
            {
                Layout layout = Prepare(policy);
                Claim claim = Read<Claim>(Path.Combine(layout.Requests, runId + ".claimed"), 1024);
                if (claim.RunId != runId || !ValidTicks(claim.CreatedUtcTicks)) throw new InvalidDataException("Script requires a valid claimed request.");
                string path = Path.Combine(layout.Requests, runId + ".ps1");
                if (File.Exists(path)) throw new IOException("Script is already staged.");
                AtomicWrite(policy, layout, path, bytes);
                return path;
            }
        }

        public static void Complete(Policy policy, string id, Dictionary<string, object> receipt)
        {
            ValidateId(id);
            if (receipt == null) throw new ArgumentNullException("receipt");
            var clean = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach (var item in receipt)
            {
                if (!ReceiptKeys.Contains(item.Key) || !IsScalar(item.Value)) throw new InvalidDataException("Receipt contains unsupported metadata.");
                if (item.Value is string && ((string)item.Value).Length > 1024) throw new InvalidDataException("Receipt metadata is oversized.");
                clean.Add(item.Key, item.Value);
            }
            clean["run_id"] = id;
            clean["completed_utc_ticks"] = DateTime.UtcNow.Ticks;
            byte[] record = Utf8.GetBytes(Json().Serialize(clean) + "\n");
            if (record.Length > RecordLimit) throw new InvalidDataException("Receipt record exceeds 8 KiB.");
            using (new Gate(policy))
            {
                Layout layout = Prepare(policy);
                string active = Path.Combine(layout.Active, id + ".json");
                if (!File.Exists(active) && !PendingIds(layout).Contains(id)) throw new IOException("Run is unknown.");
                bool canClear = true;
                if (File.Exists(active))
                {
                    ActiveRun metadata = Read<ActiveRun>(active, ActiveLimit);
                    ValidateActive(metadata);
                    int? count = WinJob.GetActiveProcesses(metadata.JobName);
                    canClear = !count.HasValue || count.Value == 0;
                }
                WriteReceipt(policy, layout, record);
                if (canClear)
                {
                    SafeDelete(Path.Combine(layout.Requests, id + ".ps1"));
                    SafeDelete(active);
                    SafeDelete(Path.Combine(layout.Active, id + ".cancel"));
                    SafeDelete(Path.Combine(layout.Requests, id + ".claimed"));
                    SafeDelete(Path.Combine(layout.Requests, id + ".json"));
                }
            }
        }

        public static void RequestCancel(Policy policy, string id)
        {
            ValidateId(id);
            using (new Gate(policy))
            {
                Layout layout = Prepare(policy);
                if (!PendingIds(layout).Contains(id) && !File.Exists(Path.Combine(layout.Active, id + ".json")))
                    throw new IOException("Run is unknown.");
                string path = Path.Combine(layout.Active, id + ".cancel");
                if (File.Exists(path)) return;
                if (FilesIn(layout, layout.Active).Count >= ActiveFiles) throw new IOException("Active state quota reached.");
                AtomicWrite(policy, layout, path, new byte[0]);
            }
        }

        public static bool IsCancelled(Policy policy, string id)
        {
            if (policy == null) throw new ArgumentNullException("policy");
            ValidateId(id);
            string runtime = Path.Combine(policy.DataRoot, "runtime");
            string active = Path.Combine(runtime, "active");
            string path = Path.Combine(active, id + ".cancel");
            CheckPath(policy.DataRoot, true);
            CheckPath(runtime, true);
            CheckPath(active, true);
            CheckPath(path, false);
            try
            {
                FileAttributes attributes = File.GetAttributes(path);
                if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                    throw new InvalidDataException("Invalid cancellation marker path.");
                if (new FileInfo(path).Length != 0) throw new InvalidDataException("Cancellation marker must be empty.");
                return true;
            }
            catch (FileNotFoundException) { return false; }
            catch (DirectoryNotFoundException) { return false; }
        }

        public static object Status(Policy policy)
        {
            using (new Gate(policy))
            {
                Layout layout = Prepare(policy);
                var active = new List<ActiveRun>();
                foreach (var file in FilesIn(layout, layout.Active).Where(f => f.Extension == ".json"))
                {
                    ActiveRun run = Read<ActiveRun>(file.FullName, ActiveLimit);
                    ValidateActive(run);
                    if (run.RunId != Path.GetFileNameWithoutExtension(file.Name)) throw new InvalidDataException("Active identity mismatch.");
                    active.Add(run);
                }
                return new { active = active, pending = PendingIds(layout).Count, runtime_bytes = layout.Bytes,
                    receipt_files = FilesIn(layout, layout.Receipts).Count, runtime_max_bytes = policy.RuntimeMaxBytes };
            }
        }

        public static void Maintain(Policy policy)
        {
            using (new Gate(policy)) { Prepare(policy, true); }
        }

        // Physical storage admission for the telemetry owner. This does not
        // create directories, parse records or recover state. Logical pressure
        // is reported separately; only Prepare/Maintain may repair that state.
        // A caller already holding the same Store mutex may call synchronously.
        public static object InspectStorage(string dataRoot, long runtimeMaxBytes, string storageOwnerSid)
        {
            if (runtimeMaxBytes < 1 || runtimeMaxBytes > Policy.MaximumRuntimeBytes)
                throw new ArgumentOutOfRangeException("runtimeMaxBytes");
            dataRoot = Policy.NormalizeDataRoot(dataRoot);
            using (new Gate(storageOwnerSid))
            {
                Layout layout = Inspect(dataRoot, runtimeMaxBytes, false);
                if (layout.Bytes > runtimeMaxBytes) throw new IOException("Runtime byte budget exceeded; no files removed.");
                return new {
                    runtime_bytes = layout.Bytes, file_count = layout.Files.Count,
                    pending = PendingIds(layout).Count,
                    active_files = FilesIn(layout, layout.Active).Count(f => !IsTemp(f.Name)),
                    receipt_files = FilesIn(layout, layout.Receipts).Count(f => !IsTemp(f.Name)),
                    temp_files = layout.Files.Count(f => IsTemp(f.Name)),
                    logical_quota_valid = !QuotasExceeded(layout, runtimeMaxBytes)
                };
            }
        }

        private static Layout Prepare(Policy policy, bool maintainExpired = false)
        {
            if (policy == null) throw new ArgumentNullException("policy");
            EnsureDirectory(policy.DataRoot);
            string root = Path.Combine(policy.DataRoot, "runtime");
            EnsureDirectory(root);
            foreach (string name in new[] { "requests", "active", "receipts" }) EnsureDirectory(Path.Combine(root, name));
            // Validate every name, path and per-file bound before deleting any
            // recognized orphan. Writers hold this same gate, so an observed
            // atomic-write temp cannot belong to a write still in progress.
            Layout layout = Inspect(policy, false);
            foreach (FileInfo file in layout.Files.Where(f => IsTemp(f.Name))) SafeDelete(file.FullName);
            layout = Inspect(policy, false);
            if (maintainExpired || QuotasExceeded(layout, policy.RuntimeMaxBytes)) MaintainLocked(policy, layout);
            return Inspect(policy);
        }

        private static Layout Inspect(Policy policy)
        { return Inspect(policy, true); }

        private static Layout Inspect(Policy policy, bool enforceQuotas)
        { return Inspect(policy.DataRoot, policy.RuntimeMaxBytes, enforceQuotas); }

        private static Layout Inspect(string dataRoot, long runtimeMaxBytes, bool enforceQuotas)
        {
            string root = Path.Combine(dataRoot, "runtime");
            var layout = new Layout { Root = root, Requests = Path.Combine(root, "requests"), Active = Path.Combine(root, "active"),
                Receipts = Path.Combine(root, "receipts"), Files = new List<FileInfo>() };
            CheckPath(root, true);
            var directories = new HashSet<string>(new[] { "requests", "active", "receipts" }, StringComparer.Ordinal);
            foreach (string entry in DirectoryPresent(root) ? Directory.EnumerateFileSystemEntries(root) : Enumerable.Empty<string>())
            {
                CheckPath(entry, Directory.Exists(entry));
                if (!Directory.Exists(entry) || !directories.Contains(Path.GetFileName(entry))) throw new InvalidDataException("Unknown runtime entry; preserved.");
            }
            foreach (string dir in new[] { layout.Requests, layout.Active, layout.Receipts })
            {
                CheckPath(dir, true);
                if (!DirectoryPresent(dir)) continue;
                foreach (string path in Directory.EnumerateFileSystemEntries(dir))
                {
                    if (layout.Files.Count >= InventoryLimit) throw new IOException("Runtime inventory exceeds bounded recovery capacity; no files removed.");
                    CheckPath(path, false);
                    if (Directory.Exists(path)) throw new InvalidDataException("Unexpected runtime subdirectory; preserved.");
                    var file = new FileInfo(path);
                    long maximum;
                    if (IsTemp(file.Name)) maximum = ReceiptFileLimit;
                    else if (dir == layout.Receipts) { ReceiptDate(file.Name); maximum = ReceiptFileLimit; }
                    else
                    {
                        string extension = file.Extension;
                        ValidateId(Path.GetFileNameWithoutExtension(file.Name));
                        if (dir == layout.Requests && (extension == ".json" || extension == ".ps1")) maximum = RequestLimit;
                        else if (dir == layout.Requests && extension == ".claimed") maximum = 1024;
                        else if (dir == layout.Active && extension == ".json") maximum = ActiveLimit;
                        else if (dir == layout.Active && extension == ".cancel") maximum = 0;
                        else throw new InvalidDataException("Unknown runtime file; preserved.");
                    }
                    if (file.Length > maximum) throw new InvalidDataException("Runtime file quota violated; preserved.");
                    layout.Bytes = checked(layout.Bytes + file.Length);
                    layout.Files.Add(file);
                }
            }
            if (enforceQuotas && QuotasExceeded(layout, runtimeMaxBytes))
                throw new IOException("Runtime quota exceeded; no files removed.");
            return layout;
        }

        private static bool QuotasExceeded(Layout layout, long runtimeMaxBytes)
        {
            return layout.Files.Count(f => IsTemp(f.Name)) > 1 || PendingIds(layout).Count > PendingLimit ||
                FilesIn(layout, layout.Active).Count(f => !IsTemp(f.Name)) > ActiveFiles ||
                FilesIn(layout, layout.Receipts).Count(f => !IsTemp(f.Name)) > ReceiptFiles || layout.Bytes > runtimeMaxBytes;
        }

        private static string StoreOwner(Policy policy)
        {
            if (policy == null) throw new ArgumentNullException("policy");
            return policy.StorageOwnerSid;
        }

        private static bool DirectoryPresent(string path)
        {
            try
            {
                FileAttributes attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.Directory) == 0 || (attributes & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("Invalid runtime directory path.");
                return true;
            }
            catch (FileNotFoundException) { return false; }
            catch (DirectoryNotFoundException) { return false; }
        }

        private static void MaintainLocked(Policy policy, Layout layout)
        {
            DateTime now = DateTime.UtcNow;
            foreach (FileInfo file in FilesIn(layout, layout.Receipts))
                if (ReceiptDate(file.Name) < now.AddDays(-policy.OrdinaryDays)) SafeDelete(file.FullName);
            var activeIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (FileInfo file in FilesIn(layout, layout.Active).Where(f => f.Extension == ".json"))
            {
                ActiveRun run = Read<ActiveRun>(file.FullName, ActiveLimit);
                ValidateActive(run);
                if (run.RunId != Path.GetFileNameWithoutExtension(file.Name)) throw new InvalidDataException("Active identity mismatch.");
                bool keep = OwnerCouldBeAlive(run);
                if (!keep)
                {
                    try { int? count = WinJob.GetActiveProcesses(run.JobName); keep = count.HasValue && count.Value > 0; }
                    catch { keep = true; }
                }
                if (keep) activeIds.Add(run.RunId);
                else { SafeDelete(file.FullName); SafeDelete(Path.Combine(layout.Active, run.RunId + ".cancel")); }
            }
            foreach (FileInfo file in FilesIn(layout, layout.Requests))
            {
                if (!File.Exists(file.FullName)) continue;
                string id = Path.GetFileNameWithoutExtension(file.Name);
                if (activeIds.Contains(id)) continue;
                long ticks;
                if (file.Extension == ".ps1")
                {
                    string claimPath = Path.Combine(layout.Requests, id + ".claimed");
                    if (!File.Exists(claimPath)) throw new InvalidDataException("Orphan script preserved.");
                    Claim claim = Read<Claim>(claimPath, 1024);
                    if (claim.RunId != id || !ValidTicks(claim.CreatedUtcTicks)) throw new InvalidDataException("Claim metadata invalid.");
                    if (claim.CreatedUtcTicks < now.AddHours(-1).Ticks) SafeDelete(file.FullName);
                    continue;
                }
                if (file.Extension == ".claimed")
                {
                    Claim claim = Read<Claim>(file.FullName, 1024);
                    if (claim.RunId != id || !ValidTicks(claim.CreatedUtcTicks)) throw new InvalidDataException("Claim metadata invalid.");
                    ticks = claim.CreatedUtcTicks;
                }
                else
                {
                    Request request = Read<Request>(file.FullName, RequestLimit);
                    ValidateRequest(policy, request);
                    if (request.RunId != id) throw new InvalidDataException("Request identity mismatch.");
                    ticks = request.CreatedUtcTicks;
                }
                if (ticks < now.AddHours(-1).Ticks)
                {
                    SafeDelete(Path.Combine(layout.Requests, id + ".ps1"));
                    SafeDelete(file.FullName);
                    SafeDelete(Path.Combine(layout.Active, id + ".cancel"));
                }
            }
            foreach (FileInfo file in FilesIn(layout, layout.Active).Where(f => f.Extension == ".cancel"))
            {
                string id = Path.GetFileNameWithoutExtension(file.Name);
                if (!activeIds.Contains(id) && !File.Exists(Path.Combine(layout.Requests, id + ".json")) && !File.Exists(Path.Combine(layout.Requests, id + ".claimed")))
                    SafeDelete(file.FullName);
            }
        }

        private static void WriteReceipt(Policy policy, Layout layout, byte[] record)
        {
            var files = FilesIn(layout, layout.Receipts).OrderBy(f => f.Name, StringComparer.Ordinal).ToList();
            FileInfo last = files.LastOrDefault();
            bool append = last != null && ReceiptDate(last.Name).Date == DateTime.UtcNow.Date && last.Length + record.Length <= ReceiptFileLimit;
            if (!append && files.Count == ReceiptFiles) { SafeDelete(files[0].FullName); files.RemoveAt(0); layout = Inspect(policy); }
            string path = append ? last.FullName : Path.Combine(layout.Receipts, DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfffffff'Z'", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N") + ".jsonl");
            byte[] prior = append ? File.ReadAllBytes(path) : new byte[0];
            byte[] content = new byte[prior.Length + record.Length];
            Buffer.BlockCopy(prior, 0, content, 0, prior.Length);
            Buffer.BlockCopy(record, 0, content, prior.Length, record.Length);
            AtomicWrite(policy, layout, path, content);
        }

        private static bool OwnerCouldBeAlive(ActiveRun run)
        {
            try
            {
                using (Process process = Process.GetProcessById(run.OwnerPid))
                    return !process.HasExited && process.StartTime.ToUniversalTime().Ticks == run.OwnerStartUtcTicks;
            }
            catch (ArgumentException) { return false; }
            catch (InvalidOperationException) { return false; }
            catch { return true; }
        }

        private static void AtomicWrite(Policy policy, Layout layout, string path, byte[] content)
        {
            CheckPath(path, false);
            if (content.Length > policy.RuntimeMaxBytes - layout.Bytes) throw new IOException("Runtime prewrite budget exhausted.");
            string temp = Path.Combine(Path.GetDirectoryName(path), ".tmp-" + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                { stream.Write(content, 0, content.Length); stream.Flush(true); }
                CheckPath(path, false);
                if (File.Exists(path)) File.Replace(temp, path, null);
                else File.Move(temp, path);
            }
            finally { if (File.Exists(temp)) SafeDelete(temp); }
        }

        private static byte[] Serialize(object value, int maximum)
        {
            byte[] bytes = Utf8.GetBytes(Json().Serialize(value));
            if (bytes.Length > maximum) throw new InvalidDataException("Runtime record is oversized.");
            return bytes;
        }
        private static JavaScriptSerializer Json() { return new JavaScriptSerializer { MaxJsonLength = ReceiptFileLimit, RecursionLimit = 12 }; }
        private static T Read<T>(string path, int maximum)
        {
            CheckPath(path, false);
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > maximum) throw new InvalidDataException("Runtime record absent or oversized.");
            T value = Json().Deserialize<T>(File.ReadAllText(path, Utf8));
            if (value == null) throw new InvalidDataException("Runtime record is null.");
            return value;
        }
        private static List<FileInfo> FilesIn(Layout layout, string directory)
        { return layout.Files.Where(f => String.Equals(f.DirectoryName, directory, StringComparison.OrdinalIgnoreCase)).ToList(); }
        private static HashSet<string> PendingIds(Layout layout)
        { return new HashSet<string>(FilesIn(layout, layout.Requests).Where(f => !IsTemp(f.Name)).Select(f => Path.GetFileNameWithoutExtension(f.Name)), StringComparer.Ordinal); }
        private static void ValidateRequest(Policy policy, Request value)
        {
            if (value == null) throw new InvalidDataException("Invalid request.");
            ValidateId(value.RunId); Text(value.Agent, 128); Text(value.Owner, 256); Text(value.Command, RequestLimit); Text(value.Cwd, 32768);
            if (!Path.IsPathRooted(value.Cwd) || value.TimeoutSeconds < 1 || value.TimeoutSeconds > policy.MaximumTimeoutSeconds || !ValidTicks(value.CreatedUtcTicks))
                throw new InvalidDataException("Invalid request bounds.");
        }
        private static void ValidateActive(ActiveRun value)
        {
            if (value == null) throw new InvalidDataException("Invalid active metadata.");
            ValidateId(value.RunId); Text(value.Agent, 128); Text(value.Owner, 256); Text(value.JobName, 240);
            const string prefix = "Global\\AgentExec-";
            if (!value.JobName.StartsWith(prefix, StringComparison.Ordinal) || value.JobName.Length <= prefix.Length ||
                value.JobName.Substring(prefix.Length).Any(c => !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) ||
                value.OwnerPid < 1 || !ValidTicks(value.OwnerStartUtcTicks) || !ValidTicks(value.StartedUtcTicks))
                throw new InvalidDataException("Invalid active ownership identity.");
        }
        private static void Text(string value, int maximum)
        { if (String.IsNullOrWhiteSpace(value) || value.Length > maximum || value.IndexOf('\0') >= 0) throw new InvalidDataException("Invalid runtime text field."); }
        private static bool ValidTicks(long ticks) { return ticks > DateTime.MinValue.Ticks && ticks <= DateTime.MaxValue.Ticks && ticks <= DateTime.UtcNow.AddMinutes(5).Ticks; }
        private static bool IsScalar(object value)
        { return value == null || value is string || value is bool || value is byte || value is sbyte || value is short || value is ushort || value is int || value is uint || value is long || value is ulong || value is decimal || value is double || value is float; }
        private static void ValidateId(string id)
        {
            Guid guid;
            if (id == null || id.Length != 32 || !Guid.TryParseExact(id, "N", out guid) || id != guid.ToString("N")) throw new InvalidDataException("Invalid run ID.");
        }
        private static bool IsTemp(string name)
        {
            if (!name.StartsWith(".tmp-", StringComparison.Ordinal) || !name.EndsWith(".tmp", StringComparison.Ordinal) || name.Length != 41) return false;
            Guid id; return Guid.TryParseExact(name.Substring(5, 32), "N", out id);
        }
        private static DateTime ReceiptDate(string name)
        {
            DateTime value; Guid id;
            if (name.Length != 62 || name[23] != '-' || !name.EndsWith(".jsonl", StringComparison.Ordinal) ||
                !Guid.TryParseExact(name.Substring(24, 32), "N", out id) ||
                !DateTime.TryParseExact(name.Substring(0, 23), "yyyyMMdd'T'HHmmssfffffff'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out value) || value > DateTime.UtcNow.AddMinutes(5))
                throw new InvalidDataException("Unknown receipt file; preserved.");
            return value;
        }
        internal static void CheckPath(string path, bool directory)
        {
            string current = Path.GetFullPath(path);
            while (!String.IsNullOrEmpty(current))
            {
                if (File.Exists(current) || Directory.Exists(current))
                {
                    FileAttributes attributes = File.GetAttributes(current);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Reparse paths are not permitted in runtime storage.");
                    if (current == Path.GetFullPath(path) && (((attributes & FileAttributes.Directory) != 0) != directory))
                        throw new InvalidDataException("Runtime path type mismatch.");
                }
                current = Path.GetDirectoryName(current);
            }
        }
        private static void EnsureDirectory(string path) { CheckPath(path, true); Directory.CreateDirectory(path); CheckPath(path, true); }
        private static void SafeDelete(string path) { CheckPath(path, false); if (File.Exists(path)) File.Delete(path); }
        private static string BuildMutexName()
        {
            // User tool processes and SYSTEM's scheduled retention share this one installed store.
            return "Global\\AgentExec-RuntimeStore-v1";
        }
    }
}
