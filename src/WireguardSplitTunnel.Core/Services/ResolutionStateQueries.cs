using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class ResolutionStateQueries
{
    public static IReadOnlyCollection<string> GetResolvedIps(AppState state, string domain)
    {
        if (state.LastKnownResolvedIps.TryGetValue(domain, out var ips))
        {
            return ips;
        }

        var match = state.LastKnownResolvedIps
            .FirstOrDefault(pair => string.Equals(pair.Key, domain, StringComparison.OrdinalIgnoreCase));

        return match.Value ?? [];
    }

    public static IReadOnlyCollection<ResolvedIpDetail> GetResolvedIpDetails(AppState state, string domain)
    {
        if (state.LastKnownResolvedIpDetails.TryGetValue(domain, out var details))
        {
            return details;
        }

        var match = state.LastKnownResolvedIpDetails
            .FirstOrDefault(pair => string.Equals(pair.Key, domain, StringComparison.OrdinalIgnoreCase));
        if (match.Value is not null)
        {
            return match.Value;
        }

        return GetResolvedIps(state, domain)
            .Select(ip => new ResolvedIpDetail(ip, domain, ResolvedIpSourceKind.Direct))
            .ToArray();
    }
}
