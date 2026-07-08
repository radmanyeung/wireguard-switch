using System.Net;
using System.Runtime.Versioning;
using System.Text;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Detects network services whose DNS was left pointing at a tunnel's resolvers
/// (wg-quick sets them via networksetup and only restores them on a clean
/// "down") and resets them to DHCP-provided DNS.
/// </summary>
public static class MacDnsRepairService
{
    internal static IReadOnlyList<string> ParseNetworkServices(string listOutput)
    {
        return listOutput
            .Replace("\r\n", "\n")
            .Split('\n')
            .Skip(1) // "An asterisk (*) denotes that a network service is disabled."
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.StartsWith('*'))
            .ToList();
    }

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

    internal static IReadOnlyList<string> PlanServicesToReset(
        IReadOnlyDictionary<string, IReadOnlyList<string>> currentDnsByService,
        IReadOnlyList<string> tunnelDns)
    {
        if (tunnelDns.Count == 0)
        {
            return [];
        }

        return currentDnsByService
            .Where(pair => pair.Value.Intersect(tunnelDns, StringComparer.OrdinalIgnoreCase).Any())
            .Select(pair => pair.Key)
            .OrderBy(service => service, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    internal static string BuildResetScript(IEnumerable<string> services)
    {
        var script = new StringBuilder();
        foreach (var service in services)
        {
            script.AppendLine($"/usr/sbin/networksetup -setdnsservers {ShellQuoting.Quote(service)} Empty");
        }

        return script.ToString();
    }

    [SupportedOSPlatform("macos")]
    public static async Task<IReadOnlyList<string>> DiscoverServicesToResetAsync(
        IReadOnlyList<string> tunnelDns,
        CancellationToken cancellationToken)
    {
        if (tunnelDns.Count == 0)
        {
            return [];
        }

        var listResult = await MacAdminShell.RunAsync(
            "/usr/sbin/networksetup", "-listallnetworkservices", cancellationToken);
        if (listResult.ExitCode != 0)
        {
            return [];
        }

        var currentDnsByService = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var service in ParseNetworkServices(listResult.StandardOutput))
        {
            var dnsResult = await MacAdminShell.RunAsync(
                "/usr/sbin/networksetup", $"-getdnsservers {ShellQuoting.Quote(service)}", cancellationToken);
            if (dnsResult.ExitCode == 0)
            {
                currentDnsByService[service] = ParseDnsServers(dnsResult.StandardOutput);
            }
        }

        return PlanServicesToReset(currentDnsByService, tunnelDns);
    }

    /// <summary>Resets the given services' DNS to DHCP. One admin prompt total.</summary>
    [SupportedOSPlatform("macos")]
    public static async Task ResetServicesAsync(IReadOnlyList<string> services, CancellationToken cancellationToken)
    {
        if (services.Count == 0)
        {
            return;
        }

        var result = await MacAdminShell.RunAsAdminAsync(
            BuildResetScript(services),
            "WireGuard split tunnel needs to restore system DNS",
            cancellationToken);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"DNS restore failed (exit {result.ExitCode}): {result.Combined}");
        }
    }
}
