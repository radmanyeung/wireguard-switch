using WireguardSplitTunnel.Core.Models;
namespace WireguardSplitTunnel.Core.Services;

public static class SoftwareDomainRouteOwnership
{
    public const string SharedDebtDomain = "__software_shared_route__";
    // Only the original tuple recorded after a confirmed domain write proves ownership.
    // Legacy IP-only ledgers stay as cleanup debt; the currently selected VPN proves nothing.
    public static async Task<HashSet<string>> TransferAsync(IEnumerable<ManagedRouteEntry> relinquishedDomainRoutes, IEnumerable<string> softwareNeeded,
        int? interfaceIndex, List<SoftwareOwnedRoute> owned, Func<SoftwareOwnedRoute, CancellationToken, Task<SoftwareOwnedRoute?>> read,
        ISoftwareRouteWriter writer, Action save, CancellationToken cancellationToken)
    {
        var transferred = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var needed = softwareNeeded.ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var debt in relinquishedDomainRoutes.Where(r => needed.Contains(r.IpAddress)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (debt.InterfaceIndex is not > 0 || debt.RouteMetric is null || string.IsNullOrWhiteSpace(debt.NextHop)) continue;
            var key = new SoftwareOwnedRoute(debt.IpAddress, debt.InterfaceIndex.Value, debt.NextHop, debt.RouteMetric.Value);
            var existing = await read(key, cancellationToken);
            if (existing is null)
            {
                transferred.Add(debt.IpAddress); // Confirmed absent: no old cleanup obligation remains.
                continue;
            }
            if (existing != key) continue; // Another owner replaced the recorded tuple; do not adopt it.
            if (!owned.Contains(existing)) owned.Add(existing);
            save(); // Durable destination debt must exist BEFORE the caller drops source debt.
            transferred.Add(debt.IpAddress);
        }
        return transferred;
    }
    public static bool CanRemoveDomainRoute(ManagedRouteEntry route, IEnumerable<string> needed, IEnumerable<SoftwareOwnedRoute> owned)
    {
        if (route.Domain == SharedDebtDomain || needed.Contains(route.IpAddress)) return false;
        var sameIpOwners = owned.Where(r => r.IpAddress == route.IpAddress).ToArray();
        if (route.InterfaceIndex is null || route.NextHop is null || route.RouteMetric is null) return sameIpOwners.Length == 0;
        return !sameIpOwners.Any(r => r.InterfaceIndex == route.InterfaceIndex && r.NextHop == route.NextHop && r.Metric == route.RouteMetric);
    }
    public static List<ManagedRouteEntry> RetainSharedDebt(IEnumerable<ManagedRouteEntry> planned, IEnumerable<ManagedRouteEntry> previous,
        IEnumerable<string> needed, IEnumerable<SoftwareOwnedRoute> owned)
    {
        var result = planned.ToList(); var wanted = needed.ToHashSet(); var ownedIps = owned.Select(r => r.IpAddress).ToHashSet();
        foreach (var old in previous)
        {
            var unverifiableOverlap = (old.InterfaceIndex is null || old.NextHop is null || old.RouteMetric is null) && ownedIps.Contains(old.IpAddress);
            if ((old.Domain == SharedDebtDomain || wanted.Contains(old.IpAddress) || unverifiableOverlap)
                && !result.Any(r => r.IpAddress == old.IpAddress)) result.Add(old with { Domain = SharedDebtDomain });
        }
        return result;
    }
    public static List<ManagedRouteEntry> PreserveMetadata(IEnumerable<ManagedRouteEntry> planned, IEnumerable<ManagedRouteEntry> ledger)
    {
        var known = ledger.Where(r => r.InterfaceIndex is not null && r.RouteMetric is not null && r.NextHop is not null)
            .GroupBy(r => r.IpAddress).ToDictionary(g => g.Key, g => g.Last());
        return planned.Select(r => known.TryGetValue(r.IpAddress, out var exact)
            ? r with { InterfaceName = exact.InterfaceName, InterfaceIndex = exact.InterfaceIndex, NextHop = exact.NextHop, RouteMetric = exact.RouteMetric }
            : r).ToList();
    }
}
