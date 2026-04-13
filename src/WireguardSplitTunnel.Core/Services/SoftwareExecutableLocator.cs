using System.Runtime.Versioning;
using Microsoft.Win32;

namespace WireguardSplitTunnel.Core.Services;

public interface ISoftwareExecutableLocator
{
    bool TryResolvePath(string processName, out string executablePath);
}

public sealed class SystemSoftwareExecutableLocator : ISoftwareExecutableLocator
{
    public bool TryResolvePath(string processName, out string executablePath)
    {
        executablePath = string.Empty;
        var exeName = NormalizeExeName(processName);
        if (string.IsNullOrWhiteSpace(exeName))
        {
            return false;
        }

        if (OperatingSystem.IsWindows()
            && (TryResolveFromRegistry(RegistryHive.CurrentUser, exeName, out executablePath)
                || TryResolveFromRegistry(RegistryHive.LocalMachine, exeName, out executablePath)))
        {
            return true;
        }

        if (TryResolveFromPathEnvironment(exeName, out executablePath))
        {
            return true;
        }

        executablePath = string.Empty;
        return false;
    }

    private static string NormalizeExeName(string processName)
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

        return value;
    }

    [SupportedOSPlatform("windows")]
    private static bool TryResolveFromRegistry(RegistryHive hive, string exeName, out string executablePath)
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var appPaths = baseKey.OpenSubKey($"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{exeName}");
                var value = appPaths?.GetValue(null) as string;
                if (!string.IsNullOrWhiteSpace(value) && File.Exists(value))
                {
                    executablePath = value;
                    return true;
                }
            }
            catch
            {
                // ignore and continue fallback chain
            }
        }

        executablePath = string.Empty;
        return false;
    }

    private static bool TryResolveFromPathEnvironment(string exeName, out string executablePath)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                var candidate = Path.Combine(dir, exeName);
                if (File.Exists(candidate))
                {
                    executablePath = candidate;
                    return true;
                }
            }
            catch
            {
                // ignore invalid path segment
            }
        }

        executablePath = string.Empty;
        return false;
    }
}
