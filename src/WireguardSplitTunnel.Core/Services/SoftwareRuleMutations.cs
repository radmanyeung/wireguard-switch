using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public enum SoftwareRulePathMutationResult
{
    Added,
    Updated,
    SkippedExisting,
    Invalid
}

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

        var normalizedPath = string.IsNullOrWhiteSpace(executablePath) ? null : executablePath.Trim();
        if (normalizedPath is not null)
        {
            if (list.Any(rule => IsSameRulePath(rule, normalized, normalizedPath)))
            {
                return false;
            }
        }
        else if (list.Any(rule => string.Equals(rule.ProcessName, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        list.Add(new SoftwareRule(normalized, true, mode, includeSubprocesses, normalizedPath));
        return true;
    }

    public static bool TrySetEnabled(AppState state, string processName, bool enabled)
    {
        return TrySetEnabled(state, processName, executablePath: null, enabled, matchPath: false);
    }

    public static bool TrySetEnabled(AppState state, string processName, string? executablePath, bool enabled)
    {
        return TrySetEnabled(state, processName, executablePath, enabled, matchPath: true);
    }

    private static bool TrySetEnabled(AppState state, string processName, string? executablePath, bool enabled, bool matchPath)
    {
        var list = state.SoftwareRules;
        if (list is null)
        {
            return false;
        }

        var index = FindIndex(list, processName, executablePath, matchPath);
        if (index < 0)
        {
            return false;
        }

        list[index] = list[index] with { Enabled = enabled };
        return true;
    }


    public static bool TrySetExecutablePath(AppState state, string processName, string executablePath)
    {
        return TrySetExecutablePath(state, processName, currentExecutablePath: null, executablePath, matchCurrentPath: false);
    }

    public static bool TrySetExecutablePath(AppState state, string processName, string? currentExecutablePath, string executablePath)
    {
        return TrySetExecutablePath(state, processName, currentExecutablePath, executablePath, matchCurrentPath: true);
    }

    private static bool TrySetExecutablePath(AppState state, string processName, string? currentExecutablePath, string executablePath, bool matchCurrentPath)
    {
        var list = state.SoftwareRules;
        if (list is null)
        {
            return false;
        }

        var index = FindIndex(list, processName, currentExecutablePath, matchCurrentPath);
        if (index < 0)
        {
            return false;
        }

        var normalized = string.IsNullOrWhiteSpace(executablePath) ? null : executablePath.Trim();
        list[index] = list[index] with { ExecutablePath = normalized };
        return true;
    }

    public static bool TrySetIncludeSubprocesses(AppState state, string processName, string? executablePath, bool includeSubprocesses)
    {
        var list = state.SoftwareRules;
        if (list is null)
        {
            return false;
        }

        var index = FindIndex(list, processName, executablePath, matchPath: true);
        if (index < 0)
        {
            return false;
        }

        list[index] = list[index] with { IncludeSubprocesses = includeSubprocesses };
        return true;
    }

    public static bool Remove(AppState state, string processName)
    {
        return Remove(state, processName, executablePath: null, matchPath: false);
    }

    public static bool Remove(AppState state, string processName, string? executablePath)
    {
        return Remove(state, processName, executablePath, matchPath: true);
    }

    private static bool Remove(AppState state, string processName, string? executablePath, bool matchPath)
    {
        var list = state.SoftwareRules;
        if (list is null)
        {
            return false;
        }

        var index = FindIndex(list, processName, executablePath, matchPath);
        if (index < 0)
        {
            return false;
        }

        list.RemoveAt(index);
        return true;
    }

    public static SoftwareRulePathMutationResult UpsertSoftwareRulePath(
        AppState state,
        string processName,
        DomainRouteMode mode,
        bool includeSubprocesses,
        string executablePath,
        Func<string, bool>? pathExists = null)
    {
        var list = state.SoftwareRules;
        if (list is null)
        {
            return SoftwareRulePathMutationResult.Invalid;
        }

        var normalized = NormalizeProcessName(processName);
        var normalizedPath = string.IsNullOrWhiteSpace(executablePath) ? string.Empty : executablePath.Trim();
        var exists = pathExists ?? File.Exists;
        if (string.IsNullOrWhiteSpace(normalized)
            || !normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(normalizedPath)
            || !exists(normalizedPath))
        {
            return SoftwareRulePathMutationResult.Invalid;
        }

        if (list.Any(rule => IsSameRulePath(rule, normalized, normalizedPath)))
        {
            return SoftwareRulePathMutationResult.SkippedExisting;
        }

        var staleIndex = list.FindIndex(rule =>
            string.Equals(rule.ProcessName, normalized, StringComparison.OrdinalIgnoreCase)
            && (string.IsNullOrWhiteSpace(rule.ExecutablePath) || !exists(rule.ExecutablePath)));
        if (staleIndex >= 0)
        {
            list[staleIndex] = list[staleIndex] with { ProcessName = normalized, ExecutablePath = normalizedPath };
            return SoftwareRulePathMutationResult.Updated;
        }

        list.Add(new SoftwareRule(normalized, true, mode, includeSubprocesses, normalizedPath));
        return SoftwareRulePathMutationResult.Added;
    }

    private static string NormalizeProcessName(string processName) => processName.Trim().ToLowerInvariant();

    private static int FindIndex(List<SoftwareRule> list, string processName, string? executablePath, bool matchPath)
    {
        var normalized = NormalizeProcessName(processName);
        return list.FindIndex(rule =>
            string.Equals(rule.ProcessName, normalized, StringComparison.OrdinalIgnoreCase)
            && (!matchPath || IsSamePath(rule.ExecutablePath, executablePath)));
    }

    private static bool IsSameRulePath(SoftwareRule rule, string processName, string executablePath)
    {
        return string.Equals(rule.ProcessName, processName, StringComparison.OrdinalIgnoreCase)
            && IsSamePath(rule.ExecutablePath, executablePath);
    }

    private static bool IsSamePath(string? left, string? right)
    {
        return string.Equals(
            string.IsNullOrWhiteSpace(left) ? null : left.Trim(),
            string.IsNullOrWhiteSpace(right) ? null : right.Trim(),
            StringComparison.OrdinalIgnoreCase);
    }
}


