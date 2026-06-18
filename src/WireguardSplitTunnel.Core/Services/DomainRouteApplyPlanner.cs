using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public sealed record DomainRouteApplyPlan(
    IReadOnlyList<ManagedRouteEntry> Snapshot,
    IReadOnlyList<string> ToAdd,
    IReadOnlyList<string> ToRemove);

public static class DomainRouteApplyPlanner
{
    public static DomainRouteApplyPlan Build(
        IEnumerable<ManagedRouteEntry> previousSnapshot,
        IEnumerable<ResolvedRule> resolvedRules)
    {
        var previousIps = previousSnapshot
            .Select(entry => entry.IpAddress)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var snapshot = resolvedRules
            .SelectMany(result => result.ResolvedIps.Select(ip => new ManagedRouteEntry(result.Rule.Domain, ip)))
            .GroupBy(entry => entry.IpAddress, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();

        var currentIps = snapshot
            .Select(entry => entry.IpAddress)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new DomainRouteApplyPlan(
            snapshot,
            currentIps,
            previousIps.Except(currentIps, StringComparer.OrdinalIgnoreCase).ToList());
    }
}
