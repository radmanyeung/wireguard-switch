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
}
