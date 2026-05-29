using System.Net;
using System.Net.Sockets;
using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public sealed record DnsCacheEntry(string HostName, string IpAddress);

public static class DnsCacheLearningService
{
    public static IReadOnlyCollection<ResolvedRule> LearnFromCache(
        IEnumerable<DomainRule> rules,
        IEnumerable<DnsCacheEntry> entries)
    {
        var enabledWildcardRules = rules
            .Where(rule => rule.Enabled
                && rule.Mode == DomainRouteMode.UseWireGuard
                && rule.Domain.StartsWith("*.", StringComparison.Ordinal))
            .ToList();

        if (enabledWildcardRules.Count == 0)
        {
            return [];
        }

        var output = new List<ResolvedRule>();

        foreach (var rule in enabledWildcardRules)
        {
            var root = rule.Domain[2..];
            var details = entries
                .Select(entry => NormalizeEntry(entry))
                .Where(entry => entry is not null)
                .Select(entry => entry!)
                .Where(entry => IsWildcardSubdomainMatch(entry.HostName, root))
                .GroupBy(entry => entry.IpAddress, StringComparer.OrdinalIgnoreCase)
                .Select(group => new ResolvedIpDetail(group.Key, group.First().HostName, ResolvedIpSourceKind.Learned))
                .OrderBy(detail => detail.IpAddress, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (details.Length == 0)
            {
                continue;
            }

            output.Add(new ResolvedRule(rule, details.Select(detail => detail.IpAddress).ToArray(), details));
        }

        return output;
    }

    private static DnsCacheEntry? NormalizeEntry(DnsCacheEntry entry)
    {
        var host = entry.HostName.Trim().TrimEnd('.').ToLowerInvariant();
        var ip = entry.IpAddress.Trim();
        if (string.IsNullOrWhiteSpace(host) || !IPAddress.TryParse(ip, out var parsed) || parsed.AddressFamily != AddressFamily.InterNetwork)
        {
            return null;
        }

        return new DnsCacheEntry(host, parsed.ToString());
    }

    private static bool IsWildcardSubdomainMatch(string hostName, string root)
    {
        return !string.Equals(hostName, root, StringComparison.OrdinalIgnoreCase)
            && hostName.EndsWith("." + root, StringComparison.OrdinalIgnoreCase);
    }
}
