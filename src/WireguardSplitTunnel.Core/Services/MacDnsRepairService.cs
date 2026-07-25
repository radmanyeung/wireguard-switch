using System.Net;
using System.Runtime.Versioning;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

public sealed record MacDnsRestorePlan
{
    public string? TunnelName { get; init; }
    public string? ConfigPath { get; init; }
    public IReadOnlyList<MacDnsServiceSnapshot> DnsServersToRestore { get; init; } = [];
    public IReadOnlyList<MacDnsServiceSnapshot> SearchDomainsToRestore { get; init; } = [];
    public IReadOnlyList<string> DnsServerServicesResolvedWithoutRestore { get; init; } = [];
    public IReadOnlyList<string> SearchDomainServicesResolvedWithoutRestore { get; init; } = [];

    public IReadOnlyList<MacDnsServiceSnapshot> ServicesToRestore =>
        DnsServersToRestore
            .Concat(SearchDomainsToRestore)
            .DistinctBy(snapshot => snapshot.ServiceName, StringComparer.OrdinalIgnoreCase)
            .ToList();

    public IReadOnlyList<string> ServicesResolvedWithoutRestore =>
        DnsServerServicesResolvedWithoutRestore
            .Concat(SearchDomainServicesResolvedWithoutRestore)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
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
            .ToList();
        var searchDomains = dnsEntries
            .Where(entry => !IPAddress.TryParse(entry, out _))
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

    public static MacRawTunnelDnsCleanupDebt? CreatePendingCleanupDebt(
        string tunnelName,
        string configPath,
        string configText,
        string journalPath)
    {
        var debt = CreateCleanupDebt(tunnelName, configPath, configText, []);
        return debt is null ? null : debt with { JournalPath = journalPath };
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

        var tunnelDnsServers = NormalizeDnsSequence(debt.TunnelDnsServers);
        var tunnelSearchDomains = NormalizeSearchDomainSequence(debt.TunnelSearchDomains);
        var dnsRestore = new List<MacDnsServiceSnapshot>();
        var searchRestore = new List<MacDnsServiceSnapshot>();
        var dnsResolved = new List<string>();
        var searchResolved = new List<string>();

        foreach (var before in debt.Services)
        {
            if (!currentDnsByService.TryGetValue(before.ServiceName, out var current))
            {
                // The service may return later; keep its exact debt until it can
                // be compared instead of guessing that it is safe to forget.
                continue;
            }

            var normalizedBefore = NormalizeSnapshot(before);
            var normalizedCurrent = NormalizeSnapshot(current);

            if (before.RestoreDnsServersPending)
            {
                PlanComponent(
                    before.ServiceName,
                    normalizedBefore.DnsServers,
                    normalizedCurrent.DnsServers,
                    tunnelDnsServers,
                    before,
                    dnsRestore,
                    dnsResolved);
            }

            if (before.RestoreSearchDomainsPending)
            {
                PlanComponent(
                    before.ServiceName,
                    normalizedBefore.SearchDomains,
                    normalizedCurrent.SearchDomains,
                    tunnelSearchDomains,
                    before,
                    searchRestore,
                    searchResolved);
            }
        }

        return new MacDnsRestorePlan
        {
            TunnelName = debt.TunnelName,
            ConfigPath = debt.ConfigPath,
            DnsServersToRestore = dnsRestore,
            SearchDomainsToRestore = searchRestore,
            DnsServerServicesResolvedWithoutRestore = dnsResolved,
            SearchDomainServicesResolvedWithoutRestore = searchResolved
        };

        static void PlanComponent(
            string serviceName,
            IReadOnlyList<string> before,
            IReadOnlyList<string> current,
            IReadOnlyList<string> tunnel,
            MacDnsServiceSnapshot snapshot,
            ICollection<MacDnsServiceSnapshot> restore,
            ICollection<string> resolved)
        {
            if (ResolverSequencesEqual(before, tunnel)
                || ResolverSequencesEqual(current, before)
                || !ResolverSequencesEqual(current, tunnel))
            {
                resolved.Add(serviceName);
                return;
            }

            restore.Add(snapshot);
        }
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
        var dnsPendingNames = plan.DnsServersToRestore
            .Select(service => service.ServiceName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var searchPendingNames = plan.SearchDomainsToRestore
            .Select(service => service.ServiceName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var remaining = debt.Services
            .Select(service => service with
            {
                RestoreDnsServersPending = service.RestoreDnsServersPending
                    && (unresolvedNames.Contains(service.ServiceName)
                        || dnsPendingNames.Contains(service.ServiceName)),
                RestoreSearchDomainsPending = service.RestoreSearchDomainsPending
                    && (unresolvedNames.Contains(service.ServiceName)
                        || searchPendingNames.Contains(service.ServiceName))
            })
            .Where(service => service.RestoreDnsServersPending
                              || service.RestoreSearchDomainsPending)
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
            DnsServers = NormalizeDnsSequence(snapshot.DnsServers).ToList(),
            SearchDomains = NormalizeSearchDomainSequence(snapshot.SearchDomains).ToList()
        };

    private static IReadOnlyList<string> NormalizeDnsSequence(IEnumerable<string> values) =>
        values
            .Select(value => IPAddress.TryParse(value.Trim(), out var address)
                ? address.ToString()
                : value.Trim())
            .ToList();

    private static IReadOnlyList<string> NormalizeSearchDomainSequence(IEnumerable<string> values) =>
        values
            .Select(value => value.Trim().TrimEnd('.').ToLowerInvariant())
            .ToList();

    private static bool ResolverSequencesEqual(
        IReadOnlyList<string> left,
        IReadOnlyList<string> right) =>
        left.SequenceEqual(right, StringComparer.OrdinalIgnoreCase);
}
