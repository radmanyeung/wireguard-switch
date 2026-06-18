using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public sealed record SoftwareRulePathRepairResult(
    int Added,
    int Updated,
    IReadOnlyList<string> UnresolvedProcessNames);

public static class SoftwareRulePathRepair
{
    public static SoftwareRulePathRepairResult RepairEnabledRulePaths(
        AppState state,
        ISoftwareExecutableLocator locator)
    {
        var list = state.SoftwareRules;
        if (list is null || list.Count == 0)
        {
            return new SoftwareRulePathRepairResult(0, 0, []);
        }

        var added = 0;
        var updated = 0;
        var unresolved = new List<string>();
        var resolutionCache = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in list.Where(rule => rule.Enabled).ToArray())
        {
            var resolvedPaths = ResolveOnce(locator, resolutionCache, rule.ProcessName);
            var currentPathExists = !string.IsNullOrWhiteSpace(rule.ExecutablePath) && File.Exists(rule.ExecutablePath);

            if (resolvedPaths.Count == 0)
            {
                if (!currentPathExists)
                {
                    AddUnresolved(unresolved, rule.ProcessName);
                }

                continue;
            }

            var missingPaths = resolvedPaths
                .Where(path => !HasRuleForPath(list, rule.ProcessName, path))
                .ToList();

            if (!currentPathExists)
            {
                if (missingPaths.Count == 0)
                {
                    if (SoftwareRuleMutations.Remove(state, rule.ProcessName, rule.ExecutablePath))
                    {
                        updated++;
                    }

                    continue;
                }

                var replacementPath = missingPaths[0];
                if (SoftwareRuleMutations.TrySetExecutablePath(state, rule.ProcessName, rule.ExecutablePath, replacementPath))
                {
                    updated++;
                    missingPaths.RemoveAt(0);
                }
            }

            foreach (var path in missingPaths)
            {
                if (SoftwareRuleMutations.TryAddSoftwareRule(
                    state,
                    rule.ProcessName,
                    rule.Mode,
                    rule.IncludeSubprocesses,
                    path))
                {
                    added++;
                }
            }
        }

        return new SoftwareRulePathRepairResult(added, updated, unresolved);
    }

    private static IReadOnlyList<string> ResolveOnce(
        ISoftwareExecutableLocator locator,
        Dictionary<string, IReadOnlyList<string>> cache,
        string processName)
    {
        if (!cache.TryGetValue(processName, out var paths))
        {
            paths = locator.ResolvePaths(processName);
            cache[processName] = paths;
        }

        return paths;
    }

    private static bool HasRuleForPath(List<SoftwareRule> rules, string processName, string executablePath)
    {
        return rules.Any(rule =>
            string.Equals(rule.ProcessName, processName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(rule.ExecutablePath?.Trim(), executablePath.Trim(), StringComparison.OrdinalIgnoreCase));
    }

    private static void AddUnresolved(List<string> unresolved, string processName)
    {
        if (!unresolved.Any(existing => string.Equals(existing, processName, StringComparison.OrdinalIgnoreCase)))
        {
            unresolved.Add(processName);
        }
    }
}
