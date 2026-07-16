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

        var removedIps = result.RemovedManagedIps.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var remainingRoutes = state.ManagedRouteSnapshot
            .Where(entry => !removedIps.Contains(entry.IpAddress))
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

        var resolvedServices = plan.ServicesResolvedWithoutRestore
            .Concat(result.RestoredDnsServices)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var remaining = debt.Services
            .Where(snapshot => !resolvedServices.Contains(snapshot.ServiceName))
            .ToList();

        return remaining.Count == 0 ? null : debt with { Services = remaining };
    }
}
