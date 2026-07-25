using System.Net;
using System.Net.Sockets;
using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public sealed record IncrementalDomainRouteApplyPlan(
    IReadOnlyList<ManagedRouteEntry> Snapshot,
    IReadOnlyList<string> ToAdd,
    IReadOnlyCollection<ResolvedRule> LearnedRules);

public static class IncrementalDomainRouteApplyPlanner
{
    public static IncrementalDomainRouteApplyPlan Build(
        AppState state,
        IEnumerable<ResolvedRule> learnedRules)
    {
        var activeRules = state.DomainRules
            .Where(IsActiveWildcardWireGuardRule)
            .GroupBy(rule => rule.Domain, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);

        var acceptedRules = learnedRules
            .Select(learnedRule => NormalizeLearnedRule(learnedRule, activeRules))
            .Where(rule => rule is not null)
            .Select(rule => rule!)
            .OrderBy(rule => rule.Rule.Domain, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var snapshot = state.ManagedRouteSnapshot.ToList();
        var snapshotIps = snapshot
            .Select(entry => entry.IpAddress)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var additions = acceptedRules
            .SelectMany(rule => rule.ResolvedIps.Select(ip => new ManagedRouteEntry(rule.Rule.Domain, ip)))
            .OrderBy(entry => entry.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ThenBy(entry => entry.Domain, StringComparer.OrdinalIgnoreCase)
            .Where(entry => snapshotIps.Add(entry.IpAddress))
            .ToList();

        snapshot.AddRange(additions);

        return new IncrementalDomainRouteApplyPlan(
            snapshot,
            additions.Select(entry => entry.IpAddress).ToList(),
            acceptedRules);
    }

    private static ResolvedRule? NormalizeLearnedRule(
        ResolvedRule learnedRule,
        IReadOnlyDictionary<string, DomainRule> activeRules)
    {
        if (!activeRules.TryGetValue(learnedRule.Rule.Domain, out var currentRule))
        {
            return null;
        }

        var ipv4s = learnedRule.ResolvedIps
            .Where(IsIpv4Address)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(ip => ip, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (ipv4s.Length == 0)
        {
            return null;
        }

        var ipv4Set = ipv4s.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var details = learnedRule.IpDetails
            .Where(detail => ipv4Set.Contains(detail.IpAddress))
            .GroupBy(detail => detail.IpAddress, StringComparer.OrdinalIgnoreCase)
            .Select(group => group
                .OrderBy(detail => detail.SourceKind == ResolvedIpSourceKind.Direct ? 0 : 1)
                .ThenBy(detail => detail.SourceHost, StringComparer.OrdinalIgnoreCase)
                .First())
            .OrderBy(detail => detail.IpAddress, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new ResolvedRule(currentRule, ipv4s, details);
    }

    private static bool IsActiveWildcardWireGuardRule(DomainRule rule)
    {
        return rule.Enabled
            && rule.Mode == DomainRouteMode.UseWireGuard
            && rule.Domain.StartsWith("*.", StringComparison.Ordinal)
            && rule.Domain.Length > 2;
    }

    private static bool IsIpv4Address(string value)
    {
        return IPAddress.TryParse(value, out var address)
            && address.AddressFamily == AddressFamily.InterNetwork;
    }
}
