using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class ResolutionStateUpdater
{
    public static void Apply(AppState state, IEnumerable<ResolvedRule> resolvedRules)
    {
        var resolvedList = resolvedRules.ToList();
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
            state.LastKnownResolvedIpDetails.Remove(key);
        }

        var detailKeysToRemove = state.LastKnownResolvedIpDetails.Keys
            .Where(domain => !enabledDomains.Contains(domain))
            .ToList();

        foreach (var key in detailKeysToRemove)
        {
            state.LastKnownResolvedIpDetails.Remove(key);
        }

        foreach (var resolvedRule in resolvedList)
        {
            var normalizedIps = resolvedRule.ResolvedIps
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(ip => ip, StringComparer.OrdinalIgnoreCase)
                .ToList();

            state.LastKnownResolvedIps[resolvedRule.Rule.Domain] = normalizedIps;
            state.LastKnownResolvedIpDetails[resolvedRule.Rule.Domain] = BuildDetails(resolvedRule, normalizedIps).ToList();
        }
    }

    private static IEnumerable<ResolvedIpDetail> BuildDetails(ResolvedRule resolvedRule, IReadOnlyCollection<string> normalizedIps)
    {
        if (resolvedRule.IpDetails.Count > 0)
        {
            return resolvedRule.IpDetails
                .GroupBy(detail => detail.IpAddress, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .OrderBy(detail => detail.IpAddress, StringComparer.OrdinalIgnoreCase);
        }

        return normalizedIps.Select(ip => new ResolvedIpDetail(ip, resolvedRule.Rule.Domain, ResolvedIpSourceKind.Direct));
    }
}
