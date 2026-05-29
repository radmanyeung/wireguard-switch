using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class ResolvedRuleMergeService
{
    public static IReadOnlyCollection<ResolvedRule> Merge(
        IEnumerable<ResolvedRule> directRules,
        IEnumerable<ResolvedRule> learnedRules)
    {
        return directRules
            .Concat(learnedRules)
            .GroupBy(rule => rule.Rule.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(group => MergeGroup(group.ToList()))
            .OrderBy(rule => rule.Rule.Domain, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static ResolvedRule MergeGroup(IReadOnlyCollection<ResolvedRule> group)
    {
        var first = group.First();
        var detailsByIp = new Dictionary<string, ResolvedIpDetail>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in group)
        {
            foreach (var detail in BuildDetails(rule))
            {
                if (!detailsByIp.TryGetValue(detail.IpAddress, out var existing)
                    || existing.SourceKind != ResolvedIpSourceKind.Direct && detail.SourceKind == ResolvedIpSourceKind.Direct)
                {
                    detailsByIp[detail.IpAddress] = detail;
                }
            }
        }

        var details = detailsByIp.Values
            .OrderBy(detail => detail.SourceKind == ResolvedIpSourceKind.Direct ? 0 : 1)
            .ThenBy(detail => detail.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new ResolvedRule(first.Rule, details.Select(detail => detail.IpAddress).ToArray(), details);
    }

    private static IEnumerable<ResolvedIpDetail> BuildDetails(ResolvedRule rule)
    {
        if (rule.IpDetails.Count > 0)
        {
            return rule.IpDetails;
        }

        return rule.ResolvedIps.Select(ip => new ResolvedIpDetail(ip, rule.Rule.Domain, ResolvedIpSourceKind.Direct));
    }
}
