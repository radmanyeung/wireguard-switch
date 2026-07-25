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

    public static bool MergeIncremental(AppState state, IEnumerable<ResolvedRule> resolvedRules)
    {
        var activeRules = state.DomainRules
            .Where(rule => rule.Enabled
                && rule.Mode == DomainRouteMode.UseWireGuard
                && rule.Domain.StartsWith("*.", StringComparison.Ordinal)
                && rule.Domain.Length > 2)
            .GroupBy(rule => rule.Domain, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        var changed = false;

        foreach (var group in resolvedRules.GroupBy(rule => rule.Rule.Domain, StringComparer.OrdinalIgnoreCase))
        {
            if (!activeRules.TryGetValue(group.Key, out var currentRule))
            {
                continue;
            }

            var domain = currentRule.Domain;
            var matchingIpKeys = FindMatchingKeys(state.LastKnownResolvedIps, domain);
            var matchingDetailKeys = FindMatchingKeys(state.LastKnownResolvedIpDetails, domain);
            var existingIps = matchingIpKeys
                .SelectMany(key => state.LastKnownResolvedIps[key])
                .ToList();
            var storedExistingDetails = matchingDetailKeys
                .SelectMany(key => state.LastKnownResolvedIpDetails[key])
                .ToList();
            var existingIpSet = existingIps.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var existingDetails = storedExistingDetails
                .Where(detail => existingIpSet.Contains(detail.IpAddress))
                .ToList();

            var detailsByIp = new Dictionary<string, ResolvedIpDetail>(StringComparer.OrdinalIgnoreCase);
            foreach (var detail in existingDetails)
            {
                AddPreferredDetail(detailsByIp, detail);
            }

            foreach (var ip in existingIps)
            {
                if (!detailsByIp.ContainsKey(ip))
                {
                    detailsByIp[ip] = new ResolvedIpDetail(ip, domain, ResolvedIpSourceKind.Direct);
                }
            }

            foreach (var resolvedRule in group)
            {
                var suppliedIps = resolvedRule.ResolvedIps
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                var suppliedIpSet = suppliedIps.ToHashSet(StringComparer.OrdinalIgnoreCase);
                var suppliedDetails = resolvedRule.IpDetails
                    .Where(detail => suppliedIpSet.Contains(detail.IpAddress))
                    .GroupBy(detail => detail.IpAddress, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(
                        detailGroup => detailGroup.Key,
                        detailGroup => detailGroup
                            .OrderBy(detail => detail.SourceKind == ResolvedIpSourceKind.Direct ? 0 : 1)
                            .ThenBy(detail => detail.SourceHost, StringComparer.OrdinalIgnoreCase)
                            .First(),
                        StringComparer.OrdinalIgnoreCase);

                foreach (var ip in suppliedIps)
                {
                    AddPreferredDetail(
                        detailsByIp,
                        suppliedDetails.TryGetValue(ip, out var detail)
                            ? detail
                            : new ResolvedIpDetail(ip, domain, ResolvedIpSourceKind.Direct));
                }
            }

            var mergedDetails = detailsByIp.Values
                .OrderBy(detail => detail.SourceKind == ResolvedIpSourceKind.Direct ? 0 : 1)
                .ThenBy(detail => detail.IpAddress, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var mergedIps = mergedDetails.Select(detail => detail.IpAddress).ToList();
            var ipsChanged = matchingIpKeys.Count != 1
                || !string.Equals(matchingIpKeys[0], domain, StringComparison.Ordinal)
                || !existingIps.SequenceEqual(mergedIps, StringComparer.OrdinalIgnoreCase);
            var detailsChanged = matchingDetailKeys.Count != 1
                || !string.Equals(matchingDetailKeys[0], domain, StringComparison.Ordinal)
                || !storedExistingDetails.SequenceEqual(mergedDetails);

            if (ipsChanged)
            {
                foreach (var key in matchingIpKeys)
                {
                    state.LastKnownResolvedIps.Remove(key);
                }

                state.LastKnownResolvedIps[domain] = mergedIps;
                changed = true;
            }

            if (detailsChanged)
            {
                foreach (var key in matchingDetailKeys)
                {
                    state.LastKnownResolvedIpDetails.Remove(key);
                }

                state.LastKnownResolvedIpDetails[domain] = mergedDetails;
                changed = true;
            }
        }

        return changed;
    }

    private static List<string> FindMatchingKeys<TValue>(
        IReadOnlyDictionary<string, TValue> dictionary,
        string domain)
    {
        return dictionary.Keys
            .Where(key => string.Equals(key, domain, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private static void AddPreferredDetail(
        IDictionary<string, ResolvedIpDetail> detailsByIp,
        ResolvedIpDetail detail)
    {
        if (!detailsByIp.TryGetValue(detail.IpAddress, out var existing)
            || existing.SourceKind != ResolvedIpSourceKind.Direct
                && detail.SourceKind == ResolvedIpSourceKind.Direct)
        {
            detailsByIp[detail.IpAddress] = detail;
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
