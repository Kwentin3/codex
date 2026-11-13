using System;
using System.IO;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace AgentExecution
{
    internal static class ShellCommand
    {
        internal static RunSpec Prepare(string command, string cwd, string requested, string scriptPath)
        {
            string shell = null, parentCommand = "";
            if (!String.IsNullOrEmpty(requested)) shell = Resolve(requested);
            else
            {
                int id = WinJob.GetParentProcessId();
                for (int level = 0; level < 4 && id > 0; level++)
                {
                    string candidate = WinJob.QueryProcessExecutable(id);
                    if (IsShell(candidate))
                    {
                        shell = candidate;
                        // The normalized hook input omits shell/profile flags. Read only the
                        // actual parent's command line for this representation decision; never log it.
                        using (ManagementObject process = new ManagementObject("Win32_Process.Handle='" + id + "'"))
                        { process.Get(); parentCommand = Convert.ToString(process["CommandLine"]); }
                        break;
                    }
                    id = WinJob.GetParentProcessId(id);
                }
            }
            if (shell == null || !File.Exists(shell)) throw new InvalidOperationException("unsupported parent shell");
            string name = Path.GetFileNameWithoutExtension(shell).ToLowerInvariant();
            string arguments;
            if (name == "powershell" || name == "pwsh")
            {
                string profile = !String.IsNullOrEmpty(requested) || NoProfile(parentCommand) ? " -NoProfile" : "";
                // Parse the original source as its own compilation unit: using/param directives
                // must remain first. A short -Command also avoids EncodedCommand's CLIXML host mode.
                string script = "try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch {}; " +
                    ". ([ScriptBlock]::Create([IO.File]::ReadAllText('" + scriptPath.Replace("'", "''") + "',[Text.Encoding]::UTF8)))";
                arguments = "-NoLogo" + profile + " -NonInteractive -Command " + QuoteWindows(script);
            }
            else if (name == "cmd") arguments = "/d /s /c \"" + command + "\"";
            else if (name == "bash" || name == "sh")
            {
                string login = BashLogin(parentCommand) ? "-l " : "";
                arguments = login + "-c " + QuoteWindows(command);
            }
            else throw new InvalidOperationException("unsupported shell");
            return new RunSpec { Executable = shell, Arguments = arguments, WorkingDirectory = cwd };
        }

        private static string Resolve(string name)
        {
            if (name == "powershell") return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");
            if (name == "cmd") return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            if (name == "bash")
            {
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Git\bin\bash.exe");
                if (File.Exists(path)) return path;
            }
            if (Path.IsPathRooted(name) && IsShell(name)) return Path.GetFullPath(name);
            throw new ArgumentException("unknown explicit shell");
        }
        private static bool IsShell(string path)
        {
            if (String.IsNullOrEmpty(path)) return false;
            string name = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
            return name == "powershell" || name == "pwsh" || name == "cmd" || name == "bash" || name == "sh";
        }
        private static bool NoProfile(string line)
        {
            foreach (string arg in Arguments(line))
            {
                string flag = arg.TrimStart('-');
                if (flag.Equals("Command", StringComparison.OrdinalIgnoreCase) || flag.Equals("EncodedCommand", StringComparison.OrdinalIgnoreCase)) break;
                if (arg.StartsWith("-") && flag.Length >= 3 && "NoProfile".StartsWith(flag, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
        private static bool BashLogin(string line)
        {
            foreach (string arg in Arguments(line))
            {
                if (arg == "--login") return true;
                if (arg.StartsWith("-") && !arg.StartsWith("--") && arg.IndexOf('l') >= 0) return true;
                if (arg == "-c" || (arg.StartsWith("-") && !arg.StartsWith("--") && arg.IndexOf('c') >= 0)) break;
            }
            return false;
        }
        private static IEnumerable<string> Arguments(string line)
        {
            if (String.IsNullOrEmpty(line)) yield break;
            int count; IntPtr block = CommandLineToArgvW(line, out count);
            if (block == IntPtr.Zero) throw new InvalidOperationException("cannot inspect parent shell options");
            try { for (int i = 1; i < count; i++) yield return Marshal.PtrToStringUni(Marshal.ReadIntPtr(block, i * IntPtr.Size)); }
            finally { LocalFree(block); }
        }
        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr CommandLineToArgvW(string command, out int count);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
        internal static string QuoteWindows(string value)
        {
            if (value.Length > 0 && !Regex.IsMatch(value, "[\\s\"]")) return value;
            StringBuilder result = new StringBuilder("\""); int slashes = 0;
            foreach (char ch in value)
            {
                if (ch == '\\') { slashes++; continue; }
                if (ch == '"') { result.Append('\\', slashes * 2 + 1); result.Append('"'); slashes = 0; continue; }
                result.Append('\\', slashes); slashes = 0; result.Append(ch);
            }
            result.Append('\\', slashes * 2); result.Append('"'); return result.ToString();
        }
    }
}
