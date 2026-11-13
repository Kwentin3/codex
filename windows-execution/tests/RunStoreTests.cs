using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using AgentExecution;

public static class RunStoreTests
{
    private static int checks;
    private static readonly JavaScriptSerializer Json = new JavaScriptSerializer();

    public static int Main(string[] args)
    {
        string tests = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory);
        string root = Path.Combine(tests, "store-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            string source = args.Length == 1 ? args[0] : Path.Combine(Path.GetDirectoryName(tests.TrimEnd('\\')), "policy.json");
            var data = (Dictionary<string, object>)Json.DeserializeObject(File.ReadAllText(source, Encoding.UTF8));
            data["storage_owner_sid"] = System.Security.Principal.WindowsIdentity.GetCurrent().User.Value;
            data["data_root"] = Path.Combine(root, "data");
            var retention = (Dictionary<string, object>)data["retention"];
            retention["runtime_max_bytes"] = 4096;
            retention["ordinary_days"] = 1;
            string policyPath = Path.Combine(root, "policy.json");
            Write(policyPath, data);
            Policy policy = Policy.Load(policyPath);
            Check(policy.RuntimeMaxBytes == 4096 && policy.OrdinaryDays == 1, "scaled policy is explicit");
            var execution = (Dictionary<string, object>)data["execution"];
            object queue = execution["queue_timeout_seconds"];
            execution.Remove("queue_timeout_seconds"); Write(policyPath, data);
            Fails(delegate { Policy.Load(policyPath); }, "missing policy does not default");
            execution["queue_timeout_seconds"] = queue; Write(policyPath, data);
            object storageOwner = data["storage_owner_sid"];
            data.Remove("storage_owner_sid"); Write(policyPath, data);
            Fails(delegate { Policy.Load(policyPath); }, "missing storage owner does not default to creator");
            data["storage_owner_sid"] = "BUILTIN\\Administrators"; Write(policyPath, data);
            Fails(delegate { Policy.Load(policyPath); }, "storage owner requires canonical native SID");
            data["storage_owner_sid"] = storageOwner; Write(policyPath, data);
            string mutexName = "Global\\AgentExec-StoreTest-" + Guid.NewGuid().ToString("N");
            using (Mutex shared = SharedMutex.Open(mutexName, policy.StorageOwnerSid)) {
                MutexSecurity acl = shared.GetAccessControl();
                string[] allowed = new[] { "S-1-5-18", "S-1-5-32-544", policy.StorageOwnerSid }.Distinct().ToArray();
                var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<MutexAccessRule>().ToArray();
                Check(acl.AreAccessRulesProtected && rules.Length == allowed.Length &&
                    rules.All(r => r.AccessControlType == AccessControlType.Allow && allowed.Contains(r.IdentityReference.Value) && r.MutexRights == MutexRights.FullControl),
                    "shared mutex birth ACL grants only SYSTEM Admin and explicit operator");
                using (Mutex same = SharedMutex.Open(mutexName, policy.StorageOwnerSid))
                    Check(same.WaitOne(1000), "same explicit owner reopens shared native mutex");
                // The second handle acquired the thread-owned object; release
                // through the still-open first handle before leaving this scope.
                shared.ReleaseMutex();
            }
            Fails(delegate { using (SharedMutex.Open("Global\\Independent-" + Guid.NewGuid().ToString("N"), policy.StorageOwnerSid)) { } }, "shared mutex rejects foreign object namespace");

            Request request = NewRequest(policy);
            string id = RunStore.CreateRequest(policy, request);
            string pending = Path.Combine(policy.DataRoot, "runtime", "requests", id + ".json");
            Check(File.Exists(pending), "request stored");
            int winners = 0;
            ThreadStart claim = delegate {
                try { RunStore.ClaimRequest(policy, id); Interlocked.Increment(ref winners); }
                catch (IOException) { }
            };
            var a = new Thread(claim); var b = new Thread(claim);
            a.Start(); b.Start(); Check(a.Join(5000) && b.Join(5000) && winners == 1, "exactly one concurrent claim");
            Check(!File.Exists(pending), "raw request removed after claim");
            string script = RunStore.StageScript(policy, id, "Write-Output '" + new String('\u044f', 800) + "'");
            byte[] scriptBytes = File.ReadAllBytes(script);
            Check(scriptBytes.Length > 3 && scriptBytes[0] == 0xef && scriptBytes[1] == 0xbb && scriptBytes[2] == 0xbf, "script uses UTF8 BOM");
            Fails(delegate { RunStore.StageScript(policy, id, "replacement"); }, "script cannot be replaced");
            using (Process self = Process.GetCurrentProcess())
                RunStore.SetActive(policy, new ActiveRun { RunId = id, Agent = "test", Owner = "store-test", JobName = "Global\\AgentExec-" + id,
                    OwnerPid = self.Id, OwnerStartUtcTicks = self.StartTime.ToUniversalTime().Ticks, StartedUtcTicks = DateTime.UtcNow.Ticks });
            RunStore.RequestCancel(policy, id);
            Check(RunStore.IsCancelled(policy, id), "cancel is observable");
            Check(new FileInfo(Path.Combine(policy.DataRoot, "runtime", "active", id + ".cancel")).Length == 0, "cancel marker is zero bytes");
            RunStore.Maintain(policy);
            string active = Path.Combine(policy.DataRoot, "runtime", "active", id + ".json");
            Check(File.Exists(active), "maintenance preserves living exact owner");
            var receipt = new Dictionary<string, object> { { "reason", "test_finished" }, { "cleanup_confirmed", true }, { "exit_code", 0 } };
            Fails(delegate { RunStore.Complete(policy, id, new Dictionary<string, object> { { "command", "private text" } }); }, "raw command receipt rejected");
            RunStore.Complete(policy, id, receipt);
            Check(!File.Exists(active) && !File.Exists(script) && !RunStore.IsCancelled(policy, id), "completion removes owned metadata and script");

            string receipts = Path.Combine(policy.DataRoot, "runtime", "receipts");
            string recent = Directory.GetFiles(receipts).Single();
            string old = Path.Combine(receipts, DateTime.UtcNow.AddDays(-2).ToString("yyyyMMdd'T'HHmmssfffffff'Z'", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N") + ".jsonl");
            File.Move(recent, old); File.SetLastWriteTimeUtc(old, DateTime.UtcNow);
            RunStore.Maintain(policy);
            Check(!File.Exists(old), "receipt age follows filename rather than LastWriteTime");

            long before = Size(policy.DataRoot);
            Request tooLarge = NewRequest(policy); tooLarge.Command = new String('x', 5000);
            Fails(delegate { RunStore.CreateRequest(policy, tooLarge); }, "prewrite budget rejects oversized admission");
            Check(Size(policy.DataRoot) == before, "failed admission leaves no temp data");
            string unknown = Path.Combine(policy.DataRoot, "runtime", "requests", "preserve.txt");
            File.WriteAllText(unknown, "independent evidence");
            Fails(delegate { RunStore.Maintain(policy); }, "unknown file fails closed");
            Check(File.Exists(unknown), "unknown file preserved"); File.Delete(unknown);

            retention["runtime_max_bytes"] = 65536; Write(policyPath, data); policy = Policy.Load(policyPath);
            var ids = new List<string>();
            for (int i = 0; i < 32; i++) ids.Add(RunStore.CreateRequest(policy, NewRequest(policy)));
            Fails(delegate { RunStore.CreateRequest(policy, NewRequest(policy)); }, "32 pending request cap");
            RunStore.ClaimRequest(policy, ids[0]);
            Fails(delegate { RunStore.CreateRequest(policy, NewRequest(policy)); }, "claimed request still consumes quota");
            RunStore.Complete(policy, ids[0], receipt);
            string replacement = RunStore.CreateRequest(policy, NewRequest(policy));
            string replacementPath = Path.Combine(policy.DataRoot, "runtime", "requests", replacement + ".json");
            Request stale = Json.Deserialize<Request>(File.ReadAllText(replacementPath)); stale.CreatedUtcTicks = DateTime.UtcNow.AddHours(-2).Ticks;
            Write(replacementPath, stale); RunStore.Maintain(policy);
            Check(!File.Exists(replacementPath), "inactive pending request expires within one hour");
            RecoveryChecks(root, data);
            Check(Size(root) < 10 * 1024 * 1024, "harness data remains below 10 MiB");
            Console.WriteLine("PASS store checks=" + checks.ToString(CultureInfo.InvariantCulture));
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine("FAIL " + error.GetType().Name + ": " + error.Message); return 1; }
        finally
        {
            string full = Path.GetFullPath(root);
            if (!full.StartsWith(tests, StringComparison.OrdinalIgnoreCase) || !Path.GetFileName(full).StartsWith("store-test-", StringComparison.Ordinal))
                throw new InvalidOperationException("Unsafe test cleanup target.");
            foreach (string entry in Directory.GetFileSystemEntries(full, "*", SearchOption.AllDirectories))
                if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Test cleanup reparse path refused.");
            Directory.Delete(full, true);
        }
    }

    private static Request NewRequest(Policy policy)
    { return new Request { Agent = "test", Owner = "store-test", Command = "Write-Output store_probe", Cwd = policy.DataRoot, TimeoutSeconds = policy.TimeoutSeconds }; }

    private static void RecoveryChecks(string root, Dictionary<string, object> source)
    {
        Policy missing = FixturePolicy(root, source, "missing", 65536, false);
        var empty = Observe(missing);
        Check((int)empty["file_count"] == 0 && !Directory.Exists(missing.DataRoot), "storage observer does not create missing layout");

        Policy cancel = FixturePolicy(root, source, "cancel", 65536);
        string cancelId = Guid.NewGuid().ToString("N");
        string marker = Path.Combine(cancel.DataRoot, "runtime", "active", cancelId + ".cancel");
        string unrelated = Path.Combine(cancel.DataRoot, "runtime", "requests", "preserve.txt");
        File.WriteAllText(unrelated, "unrelated unknown record");
        File.WriteAllBytes(marker, new byte[0]);
        Check(RunStore.IsCancelled(cancel, cancelId), "cancel read ignores unrelated invalid storage without sweeping it");
        Check(File.ReadAllText(unrelated) == "unrelated unknown record", "cancel read preserves unrelated files");
        using (var held = new ManualResetEventSlim(false))
        using (var release = new ManualResetEventSlim(false))
        using (var done = new ManualResetEventSlim(false))
        {
            Exception holderError = null, probeError = null;
            bool observed = false;
            var holder = new Thread(delegate() {
                try {
                    using (var gate = new Mutex(false, "Global\\AgentExec-RuntimeStore-v1")) {
                        bool owned = false;
                        try {
                            try { owned = gate.WaitOne(5000); } catch (AbandonedMutexException) { owned = true; }
                            if (!owned) throw new IOException("Cancellation probe could not hold Store mutex.");
                            held.Set();
                            if (!release.Wait(5000)) throw new IOException("Cancellation probe release timed out.");
                        } finally { if (owned) gate.ReleaseMutex(); }
                    }
                } catch (Exception error) { holderError = error; held.Set(); }
            });
            var probe = new Thread(delegate() {
                try { observed = RunStore.IsCancelled(cancel, cancelId); }
                catch (Exception error) { probeError = error; }
                finally { done.Set(); }
            });
            holder.Start();
            bool completed = false;
            try {
                if (!held.Wait(5000) || holderError != null) throw new IOException("Cancellation mutex probe failed to start.");
                probe.Start(); completed = done.Wait(1000);
            } finally {
                release.Set();
                if (!holder.Join(5000)) throw new IOException("Cancellation mutex holder did not stop.");
                if (probe.ThreadState != System.Threading.ThreadState.Unstarted && !probe.Join(5000)) throw new IOException("Cancellation probe did not stop.");
            }
            Check(completed && observed && holderError == null && probeError == null, "cancel read completes while another thread owns Store mutex");
        }
        File.WriteAllText(marker, "x");
        Fails(delegate { RunStore.IsCancelled(cancel, cancelId); }, "nonempty cancel marker fails closed");
        File.Delete(marker);
        Check(!RunStore.IsCancelled(cancel, cancelId), "absent cancel marker returns false without maintenance");

        Policy temps = FixturePolicy(root, source, "temps", 4096);
        string tempOne = Temp(temps, "requests", 2500), tempTwo = Temp(temps, "receipts", 2500);
        Fails(delegate { RunStore.InspectStorage(temps.DataRoot, temps.RuntimeMaxBytes, temps.StorageOwnerSid); }, "observer rejects aggregate bytes before any mutation");
        Check(File.Exists(tempOne) && File.Exists(tempTwo), "read-only overbudget observation preserves both synthetic temps");
        RunStore.Maintain(temps);
        Check(!File.Exists(tempOne) && !File.Exists(tempTwo) && (int)Observe(temps)["file_count"] == 0, "two recognized temps recover before final byte and temp quotas");

        Policy logical = FixturePolicy(root, source, "logical", 65536);
        Temp(logical, "requests", 0); Temp(logical, "receipts", 0);
        var pressure = Observe(logical);
        Check(!(bool)pressure["logical_quota_valid"] && (int)pressure["temp_files"] == 2 && (int)pressure["file_count"] == 2, "observer reports logical pressure without deleting recognized temps");
        RunStore.Maintain(logical);
        Check((bool)Observe(logical)["logical_quota_valid"], "native maintenance resolves reported temp pressure");

        Policy unknown = FixturePolicy(root, source, "unknown", 65536);
        string savedTemp = Temp(unknown, "requests", 1);
        string note = Path.Combine(unknown.DataRoot, "runtime", "requests", "user-note.txt");
        File.WriteAllText(note, "preserve independent bytes");
        Fails(delegate { RunStore.Maintain(unknown); }, "unknown name blocks recovery preflight");
        Check(File.Exists(savedTemp) && File.ReadAllText(note) == "preserve independent bytes", "failed namespace preflight preserves temps and unknown bytes");
        Fails(delegate { Observe(unknown); }, "observer rejects same unknown namespace");

        Policy oversized = FixturePolicy(root, source, "oversized", 1024 * 1024);
        string largeTemp = Temp(oversized, "requests", 512 * 1024 + 1);
        Fails(delegate { RunStore.Maintain(oversized); }, "oversized temp is not treated as recoverable owned state");
        Check(new FileInfo(largeTemp).Length == 512 * 1024 + 1, "oversized temp preserved on rejection");

        Policy receipts = FixturePolicy(root, source, "expired-receipts", 4096);
        string old = Receipt(receipts, DateTime.UtcNow.AddDays(-2), 3500);
        string recent = Receipt(receipts, DateTime.UtcNow, 2000);
        RunStore.Status(receipts);
        Check(!File.Exists(old) && new FileInfo(recent).Length == 2000, "expired receipt recovers quota before final inspection without dropping recent receipt");
        string excess = Receipt(receipts, DateTime.UtcNow, 2500);
        Fails(delegate { RunStore.Maintain(receipts); }, "unexpired overbudget receipts fail closed");
        Check(File.Exists(recent) && File.Exists(excess), "quota refusal does not drop unexpired receipts");

        Policy pending = FixturePolicy(root, source, "expired-pending", 65536);
        for (int i = 0; i < 33; i++) {
            Request item = NewRequest(pending); item.RunId = Guid.NewGuid().ToString("N"); item.CreatedUtcTicks = DateTime.UtcNow.AddHours(-2).Ticks;
            Write(Path.Combine(pending.DataRoot, "runtime", "requests", item.RunId + ".json"), item);
        }
        Check(!(bool)Observe(pending)["logical_quota_valid"], "observer reports extra expired pending records without parsing them");
        RunStore.Status(pending);
        Check((int)Observe(pending)["pending"] == 0, "expired valid pending records recover before final count quota");

        Policy malformed = FixturePolicy(root, source, "malformed", 65536);
        string invalidRecord = Path.Combine(malformed.DataRoot, "runtime", "requests", Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(invalidRecord, "{}");
        Check((bool)Observe(malformed)["logical_quota_valid"], "physical observer does not interpret record JSON");
        Fails(delegate { RunStore.Maintain(malformed); }, "semantic malformed record still fails native maintenance");
        Check(File.ReadAllText(invalidRecord) == "{}", "malformed record bytes remain available for diagnosis");

        Policy inventory = FixturePolicy(root, source, "inventory", 65536);
        for (int i = 0; i < 170; i++) Temp(inventory, "requests", 0);
        Fails(delegate { Observe(inventory); }, "zero-byte inventory has a finite structural scan limit");
        Fails(delegate { RunStore.Maintain(inventory); }, "recovery cannot bypass bounded structural scan");
        Check(Directory.GetFiles(Path.Combine(inventory.DataRoot, "runtime", "requests")).Length == 170, "inventory refusal preserves all files");
    }

    private static Policy FixturePolicy(string root, Dictionary<string, object> source, string name, long bytes, bool initialize = true)
    {
        var data = (Dictionary<string, object>)Json.DeserializeObject(Json.Serialize(source));
        data["data_root"] = Path.Combine(root, name);
        ((Dictionary<string, object>)data["retention"])["runtime_max_bytes"] = bytes;
        string path = Path.Combine(root, name + "-policy.json"); Write(path, data);
        Policy policy = Policy.Load(path);
        if (initialize) RunStore.Status(policy);
        return policy;
    }
    private static Dictionary<string, object> Observe(Policy policy)
    { return (Dictionary<string, object>)Json.DeserializeObject(Json.Serialize(RunStore.InspectStorage(policy.DataRoot, policy.RuntimeMaxBytes, policy.StorageOwnerSid))); }
    private static string Temp(Policy policy, string bucket, int bytes)
    {
        string path = Path.Combine(policy.DataRoot, "runtime", bucket, ".tmp-" + Guid.NewGuid().ToString("N") + ".tmp");
        File.WriteAllBytes(path, new byte[bytes]); return path;
    }
    private static string Receipt(Policy policy, DateTime started, int bytes)
    {
        string path = Path.Combine(policy.DataRoot, "runtime", "receipts", started.ToString("yyyyMMdd'T'HHmmssfffffff'Z'", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N") + ".jsonl");
        File.WriteAllBytes(path, new byte[bytes]); return path;
    }
    private static void Write(string path, object value) { File.WriteAllText(path, Json.Serialize(value), new UTF8Encoding(false)); }
    private static long Size(string root) { return Directory.GetFiles(root, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length); }
    private static void Check(bool condition, string label) { if (!condition) throw new InvalidOperationException(label); checks++; }
    private static void Fails(Action action, string label)
    { bool failed = false; try { action(); } catch (IOException) { failed = true; } catch (InvalidDataException) { failed = true; } catch (ArgumentException) { failed = true; } Check(failed, label); }
}
