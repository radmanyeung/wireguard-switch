using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class SoftwareRuleMutations
{
    public static bool TryAddSoftwareRule(
        AppState state,
        string processName,
        DomainRouteMode mode = DomainRouteMode.UseWireGuard,
        bool includeSubprocesses = true,
        string? executablePath = null)
    {
        var list = state.SoftwareRules;
        if (list is null)
        {
            return false;
        }

        var normalized = NormalizeProcessName(processName);
        if (string.IsNullOrWhiteSpace(normalized) || !normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (list.Any(rule => string.Equals(rule.ProcessName, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        var normalizedPath = string.IsNullOrWhiteSpace(executablePath) ? null : executablePath.Trim();
        list.Add(new SoftwareRule(normalized, true, mode, includeSubprocesses, normalizedPath));
        return true;
    }

    public static bool TrySetEnabled(AppState state, string processName, bool enabled)
    {
        var list = state.SoftwareRules;
        if (list is null)
        {
            return false;
        }

        var index = list.FindIndex(rule => string.Equals(rule.ProcessName, processName, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return false;
        }

        list[index] = list[index] with { Enabled = enabled };
        return true;
    }


    public static bool TrySetExecutablePath(AppState state, string processName, string executablePath)
    {
        var list = state.SoftwareRules;
        if (list is null)
        {
            return false;
        }

        var index = list.FindIndex(rule => string.Equals(rule.ProcessName, processName, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return false;
        }

        var normalized = string.IsNullOrWhiteSpace(executablePath) ? null : executablePath.Trim();
        list[index] = list[index] with { ExecutablePath = normalized };
        return true;
    }

    public static bool Remove(AppState state, string processName)
    {
        var list = state.SoftwareRules;
        if (list is null)
        {
            return false;
        }

        var index = list.FindIndex(rule => string.Equals(rule.ProcessName, processName, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return false;
        }

        list.RemoveAt(index);
        return true;
    }

    private static string NormalizeProcessName(string processName) => processName.Trim().ToLowerInvariant();
}


