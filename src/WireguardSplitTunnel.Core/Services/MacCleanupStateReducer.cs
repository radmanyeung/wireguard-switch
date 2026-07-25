using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class MacCleanupStateReducer
{
    public static AppState Apply(
        AppState state,
        MacCleanupRequest request,
        MacCleanupResult result)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);

        if (result.Cancelled)
        {
            return state;
        }

        var splitConfigPath = state.ActiveSplitTunnelConfigPath;
        if (result.SplitTunnelStopped
            && string.Equals(
                splitConfigPath,
                request.SplitConfigPath,
                StringComparison.OrdinalIgnoreCase))
        {
            splitConfigPath = null;
        }

        var rawTunnelName = state.ActiveRawTunnelName;
        if (result.RawTunnelStopped
            && string.Equals(
                rawTunnelName,
                request.RawTunnelName,
                StringComparison.OrdinalIgnoreCase))
        {
            rawTunnelName = null;
        }

        var resolvedRoutes = result.DeletedManagedRoutes
            .Concat(result.AlreadyAbsentManagedRoutes)
            .Concat(result.ReplacedManagedRoutes)
            .ToHashSet(ManagedRouteIdentityComparer.Instance);
        var remainingRoutes = state.ManagedRouteSnapshot
            .Where(entry => !resolvedRoutes.Contains(entry))
            .ToList();

        var dnsDebt = ReduceDnsDebt(state.RawTunnelDnsCleanupDebt, request, result);

        return state with
        {
            ActiveSplitTunnelConfigPath = splitConfigPath,
            ActiveRawTunnelName = rawTunnelName,
            ManagedRouteSnapshot = remainingRoutes,
            RawTunnelDnsCleanupDebt = dnsDebt
        };
    }

    private static MacRawTunnelDnsCleanupDebt? ReduceDnsDebt(
        MacRawTunnelDnsCleanupDebt? debt,
        MacCleanupRequest request,
        MacCleanupResult result)
    {
        var plan = request.DnsRestorePlan;
        if (debt is null
            || !string.Equals(debt.TunnelName, plan.TunnelName, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(debt.ConfigPath, plan.ConfigPath, StringComparison.OrdinalIgnoreCase))
        {
            return debt;
        }

        var resolvedDnsServices = plan.DnsServerServicesResolvedWithoutRestore
            .Concat(result.RestoredDnsServerServices)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var resolvedSearchServices = plan.SearchDomainServicesResolvedWithoutRestore
            .Concat(result.RestoredSearchDomainServices)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var remaining = debt.Services
            .Select(snapshot => snapshot with
            {
                RestoreDnsServersPending = snapshot.RestoreDnsServersPending
                    && !resolvedDnsServices.Contains(snapshot.ServiceName),
                RestoreSearchDomainsPending = snapshot.RestoreSearchDomainsPending
                    && !resolvedSearchServices.Contains(snapshot.ServiceName)
            })
            .Where(snapshot => snapshot.RestoreDnsServersPending
                               || snapshot.RestoreSearchDomainsPending)
            .ToList();

        return remaining.Count == 0 ? null : debt with { Services = remaining };
    }

    private sealed class ManagedRouteIdentityComparer : IEqualityComparer<ManagedRouteEntry>
    {
        internal static ManagedRouteIdentityComparer Instance { get; } = new();

        public bool Equals(ManagedRouteEntry? x, ManagedRouteEntry? y) =>
            x is not null
            && y is not null
            && string.Equals(x.IpAddress, y.IpAddress, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.InterfaceName, y.InterfaceName, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode(ManagedRouteEntry obj) =>
            HashCode.Combine(
                StringComparer.OrdinalIgnoreCase.GetHashCode(obj.IpAddress),
                obj.InterfaceName is null
                    ? 0
                    : StringComparer.OrdinalIgnoreCase.GetHashCode(obj.InterfaceName));
    }
}
