using System.Net;
using System.Runtime.Versioning;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

public sealed record MacDnsRestorePlan
{
    public string? TunnelName { get; init; }
    public string? ConfigPath { get; init; }
    public IReadOnlyList<MacDnsServiceSnapshot> ServicesToRestore { get; init; } = [];
    public IReadOnlyList<string> ServicesResolvedWithoutRestore { get; init; } = [];
}

/// <summary>
/// Captures exact DNS/search-domain state before a raw wg-quick tunnel and
/// plans restoration only while the persisted resolver provenance still proves
/// that the current values belong to that tunnel.
/// </summary>
public static class MacDnsRepairService
{
    internal static IReadOnlyList<string> ParseDnsServers(string getDnsOutput)
    {
        // Output is either one IP per line, or a sentence like
        // "There aren't any DNS Servers set on Wi-Fi." — only keep valid IPs.
        return getDnsOutput
            .Replace("\r\n", "\n")
            .Split('\n')
            .Select(line => line.Trim())
            .Where(line => IPAddress.TryParse(line, out _))
            .ToList();
    }

    internal static IReadOnlyList<string> ParseSearchDomains(string getSearchOutput)
    {
        return getSearchOutput
            .Replace("\r\n", "\n")
            .Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.Any(char.IsWhiteSpace))
            .ToList();
    }

    public static MacRawTunnelDnsCleanupDebt? CreateCleanupDebt(
        string tunnelName,
        string configPath,
        string configText,
        IReadOnlyList<MacDnsServiceSnapshot> before)
    {
        var dnsEntries = MacSplitTunnelConfigService.ExtractDnsServers(configText);
        var dnsServers = dnsEntries
            .Where(entry => IPAddress.TryParse(entry, out _))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var searchDomains = dnsEntries
            .Where(entry => !IPAddress.TryParse(entry, out _))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (dnsServers.Count == 0 && searchDomains.Count == 0)
        {
            return null;
        }

        return new MacRawTunnelDnsCleanupDebt(
            tunnelName,
            configPath,
            dnsServers,
            searchDomains,
            before.Select(NormalizeSnapshot).ToList());
    }

    public static MacDnsRestorePlan PlanSnapshotRestore(
        MacRawTunnelDnsCleanupDebt? debt,
        IReadOnlyDictionary<string, MacDnsServiceSnapshot>? currentDnsByService)
    {
        if (debt is null)
        {
            return new MacDnsRestorePlan();
        }

        ArgumentNullException.ThrowIfNull(currentDnsByService);

        var tunnelState = new MacDnsServiceSnapshot(
            string.Empty,
            debt.TunnelDnsServers,
            debt.TunnelSearchDomains);
        var restore = new List<MacDnsServiceSnapshot>();
        var resolved = new List<string>();

        foreach (var before in debt.Services)
        {
            if (!currentDnsByService.TryGetValue(before.ServiceName, out var current))
            {
                // The service may return later; keep its exact debt until it can
                // be compared instead of guessing that it is safe to forget.
                continue;
            }

            if (SnapshotsEqual(before, tunnelState)
                || SnapshotsEqual(current, before)
                || !SnapshotsEqual(current, tunnelState))
            {
                // Either the matching DNS pre-dated this app, wg-quick already
                // restored it, or another owner (for example MagicDNS) has
                // replaced it. None of those states belongs to this app now.
                resolved.Add(before.ServiceName);
                continue;
            }

            restore.Add(before);
        }

        return new MacDnsRestorePlan
        {
            TunnelName = debt.TunnelName,
            ConfigPath = debt.ConfigPath,
            ServicesToRestore = restore,
            ServicesResolvedWithoutRestore = resolved
        };
    }

    public static MacRawTunnelDnsCleanupDebt? RefineCleanupDebtAfterStart(
        MacRawTunnelDnsCleanupDebt debt,
        IReadOnlyDictionary<string, MacDnsServiceSnapshot> currentDnsByService)
    {
        var plan = PlanSnapshotRestore(debt, currentDnsByService);
        var unresolvedNames = debt.Services
            .Where(service => !currentDnsByService.ContainsKey(service.ServiceName))
            .Select(service => service.ServiceName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var keptNames = plan.ServicesToRestore
            .Select(service => service.ServiceName)
            .Concat(unresolvedNames)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var remaining = debt.Services
            .Where(service => keptNames.Contains(service.ServiceName))
            .ToList();

        return remaining.Count == 0 ? null : debt with { Services = remaining };
    }

    [SupportedOSPlatform("macos")]
    public static async Task<IReadOnlyList<MacDnsServiceSnapshot>> CaptureSnapshotAsync(
        CancellationToken cancellationToken)
    {
        var listResult = await MacAdminShell.RunAsync(
            "/usr/sbin/networksetup",
            "-listallnetworkservices",
            cancellationToken);
        if (listResult.ExitCode != 0)
        {
            throw new InvalidOperationException("Could not capture the current macOS DNS services.");
        }

        var snapshots = new List<MacDnsServiceSnapshot>();
        foreach (var service in ParseAllNetworkServices(listResult.StandardOutput))
        {
            var dnsResult = await MacAdminShell.RunAsync(
                "/usr/sbin/networksetup",
                $"-getdnsservers {ShellQuoting.Quote(service)}",
                cancellationToken);
            var searchResult = await MacAdminShell.RunAsync(
                "/usr/sbin/networksetup",
                $"-getsearchdomains {ShellQuoting.Quote(service)}",
                cancellationToken);
            if (dnsResult.ExitCode != 0 || searchResult.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    $"Could not capture the current DNS state for network service '{service}'.");
            }

            snapshots.Add(new MacDnsServiceSnapshot(
                service,
                ParseDnsServers(dnsResult.StandardOutput).ToList(),
                ParseSearchDomains(searchResult.StandardOutput).ToList()));
        }

        return snapshots;
    }

    public static IReadOnlyDictionary<string, MacDnsServiceSnapshot> ToSnapshotMap(
        IEnumerable<MacDnsServiceSnapshot> snapshots) =>
        snapshots
            .GroupBy(snapshot => snapshot.ServiceName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => NormalizeSnapshot(group.Last()),
                StringComparer.OrdinalIgnoreCase);

    private static IReadOnlyList<string> ParseAllNetworkServices(string listOutput)
    {
        return listOutput
            .Replace("\r\n", "\n")
            .Split('\n')
            .Skip(1)
            .Select(line => line.Trim().TrimStart('*').Trim())
            .Where(line => line.Length > 0)
            .ToList();
    }

    private static MacDnsServiceSnapshot NormalizeSnapshot(MacDnsServiceSnapshot snapshot) =>
        snapshot with
        {
            DnsServers = snapshot.DnsServers
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            SearchDomains = snapshot.SearchDomains
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList()
        };

    private static bool SnapshotsEqual(
        MacDnsServiceSnapshot left,
        MacDnsServiceSnapshot right) =>
        left.DnsServers.ToHashSet(StringComparer.OrdinalIgnoreCase)
            .SetEquals(right.DnsServers)
        && left.SearchDomains.ToHashSet(StringComparer.OrdinalIgnoreCase)
            .SetEquals(right.SearchDomains);
}
