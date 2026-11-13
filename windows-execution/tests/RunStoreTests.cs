using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
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
    private static void Write(string path, object value) { File.WriteAllText(path, Json.Serialize(value), new UTF8Encoding(false)); }
    private static long Size(string root) { return Directory.GetFiles(root, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length); }
    private static void Check(bool condition, string label) { if (!condition) throw new InvalidOperationException(label); checks++; }
    private static void Fails(Action action, string label)
    { bool failed = false; try { action(); } catch (IOException) { failed = true; } catch (InvalidDataException) { failed = true; } catch (ArgumentException) { failed = true; } Check(failed, label); }
}
