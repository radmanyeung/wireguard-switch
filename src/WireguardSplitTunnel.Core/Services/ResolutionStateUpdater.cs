using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class ResolutionStateUpdater
{
    public static void Apply(AppState state, IEnumerable<ResolvedRule> resolvedRules)
    {
        var enabledDomains = state.DomainRules
            .Where(rule => rule.Enabled)
            .Select(rule => rule.Domain)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var keysToRemove = state.LastKnownResolvedIps.Keys
            .Where(domain => !enabledDomains.Contains(domain))
            .ToList();

        foreach (var key in keysToRemove)
        {
            state.LastKnownResolvedIps.Remove(key);
        }

        foreach (var resolvedRule in resolvedRules)
        {
            var normalizedIps = resolvedRule.ResolvedIps
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(ip => ip, StringComparer.OrdinalIgnoreCase)
                .ToList();

            state.LastKnownResolvedIps[resolvedRule.Rule.Domain] = normalizedIps;
        }
    }
}
