using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace WireguardSplitTunnel.Core.Services;

public interface ISoftwareExecutableLocator
{
    bool TryResolvePath(string processName, out string executablePath);
    IReadOnlyList<string> ResolvePaths(string processName);
}

public sealed class SystemSoftwareExecutableLocator : ISoftwareExecutableLocator
{
    public bool TryResolvePath(string processName, out string executablePath)
    {
        var paths = ResolvePaths(processName);
        executablePath = paths.FirstOrDefault() ?? string.Empty;
        return paths.Count > 0;
    }

    public IReadOnlyList<string> ResolvePaths(string processName)
    {
        var exeName = SoftwareExecutableLocator.NormalizeExeName(processName);
        if (string.IsNullOrWhiteSpace(exeName))
        {
            return [];
        }

        return SoftwareExecutableLocator.NormalizeResolvedPaths(
            exeName,
            ResolveFromRunningProcesses(exeName),
            ResolveFromRegistryAndPath(exeName),
            ResolveFromVsCodeExtensions(exeName));
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<string?> ResolveFromRegistry(RegistryHive hive, string exeName)
    {
        var paths = new List<string?>();
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var appPaths = baseKey.OpenSubKey($"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{exeName}");
                var value = appPaths?.GetValue(null) as string;
                if (!string.IsNullOrWhiteSpace(value))
                {
                    paths.Add(value);
                }
            }
            catch
            {
                // ignore and continue fallback chain
            }
        }

        return paths;
    }

    private static IEnumerable<string?> ResolveFromRegistryAndPath(string exeName)
    {
        if (OperatingSystem.IsWindows())
        {
            foreach (var path in ResolveFromRegistry(RegistryHive.CurrentUser, exeName))
            {
                yield return path;
            }

            foreach (var path in ResolveFromRegistry(RegistryHive.LocalMachine, exeName))
            {
                yield return path;
            }
        }

        foreach (var path in ResolveFromPathEnvironment(exeName))
        {
            yield return path;
        }
    }

    private static IReadOnlyList<string?> ResolveFromPathEnvironment(string exeName)
    {
        var paths = new List<string?>();
        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                var candidate = Path.Combine(dir, exeName);
                paths.Add(candidate);
            }
            catch
            {
                // ignore invalid path segment
            }
        }

        return paths;
    }

    private static IReadOnlyList<string?> ResolveFromRunningProcesses(string exeName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        var paths = new List<string?>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var path = process.MainModule?.FileName;
                    if (SoftwareExecutableLocator.IsMatchingExecutablePath(exeName, path))
                    {
                        paths.Add(path);
                    }
                }
                catch
                {
                    // Protected processes are expected; skip unreadable paths.
                }
            }
        }

        return paths;
    }

    private static IEnumerable<string?> ResolveFromVsCodeExtensions(string exeName)
    {
        if (!exeName.Equals("codex-command-runner.exe", StringComparison.OrdinalIgnoreCase))
        {
            yield break;
        }

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(userProfile))
        {
            yield break;
        }

        var extensionRoot = Path.Combine(userProfile, ".vscode", "extensions");
        if (!Directory.Exists(extensionRoot))
        {
            yield break;
        }

        foreach (var directory in Directory.EnumerateDirectories(extensionRoot, "openai.chatgpt-*", SearchOption.TopDirectoryOnly))
        {
            yield return Path.Combine(directory, "bin", "windows-x86_64", exeName);
        }
    }
}

public static class SoftwareExecutableLocator
{
    public static IReadOnlyList<string> NormalizeResolvedPaths(
        string processName,
        IEnumerable<string?> runningProcessPaths,
        IEnumerable<string?> registryAndPathPaths,
        IEnumerable<string?> extensionPaths)
    {
        var exeName = NormalizeExeName(processName);
        if (string.IsNullOrWhiteSpace(exeName))
        {
            return [];
        }

        var results = new List<string>();
        AddMatchingPaths(results, exeName, runningProcessPaths);
        AddMatchingPaths(results, exeName, registryAndPathPaths);
        AddMatchingPaths(results, exeName, extensionPaths.OrderByDescending(GetExtensionVersion));
        return results;
    }

    public static string NormalizeExeName(string processName)
    {
        var value = processName.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        if (!value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            value += ".exe";
        }

        return value.ToLowerInvariant();
    }

    internal static bool IsMatchingExecutablePath(string exeName, string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return false;
        }

        var path = executablePath.Trim();
        if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
        {
            return false;
        }

        return string.Equals(Path.GetFileName(path), exeName, StringComparison.OrdinalIgnoreCase);
    }

    private static void AddMatchingPaths(List<string> results, string exeName, IEnumerable<string?> candidates)
    {
        foreach (var candidate in candidates)
        {
            if (!IsMatchingExecutablePath(exeName, candidate))
            {
                continue;
            }

            var normalized = candidate!.Trim();
            if (results.Any(existing => string.Equals(existing, normalized, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            results.Add(normalized);
        }
    }

    private static Version GetExtensionVersion(string? executablePath)
    {
        var name = executablePath?
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .FirstOrDefault(part => part.StartsWith("openai.chatgpt-", StringComparison.OrdinalIgnoreCase));

        if (string.IsNullOrWhiteSpace(name))
        {
            return new Version(0, 0);
        }

        const string prefix = "openai.chatgpt-";
        var suffix = name[prefix.Length..];
        var versionText = suffix.Split('-', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
        return Version.TryParse(versionText, out var version)
            ? version
            : new Version(0, 0);
    }
}
