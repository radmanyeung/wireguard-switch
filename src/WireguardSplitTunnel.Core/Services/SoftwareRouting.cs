using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using WireguardSplitTunnel.Core.Models;
namespace WireguardSplitTunnel.Core.Services;

public sealed record SoftwareProcess(int ProcessId, int ParentProcessId, long CreationTime, string ExecutablePath);
public sealed record SoftwareTcpConnection(int ProcessId, string RemoteAddress);
public sealed record SoftwareConnectionSnapshot(IReadOnlyList<SoftwareProcess> Processes, IReadOnlyList<SoftwareTcpConnection> Connections)
{
    // Bracket the TCP table with process snapshots. A PID alone is never an identity.
    public static SoftwareConnectionSnapshot Validate(IReadOnlyList<SoftwareProcess> before, IReadOnlyList<SoftwareTcpConnection> connections, IReadOnlyList<SoftwareProcess> after)
    {
        var previous = before.ToDictionary(p => p.ProcessId);
        var stable = after.Where(p => p.CreationTime > 0 && previous.TryGetValue(p.ProcessId, out var old)
            && old.CreationTime == p.CreationTime && old.ParentProcessId == p.ParentProcessId
            && string.Equals(old.ExecutablePath, p.ExecutablePath, StringComparison.OrdinalIgnoreCase)).ToArray();
        var ids = stable.Select(p => p.ProcessId).ToHashSet();
        return new(stable, connections.Where(c => ids.Contains(c.ProcessId)).ToArray());
    }
}
public sealed record SoftwareLearnedDestinations(string Fingerprint, List<string> IpAddresses);
public sealed record SoftwareOwnedRoute(string IpAddress, int InterfaceIndex, string NextHop, int Metric);
public sealed record SoftwareObservation(List<SoftwareLearnedDestinations> Learned, Dictionary<string, int> ChildCounts);

public sealed class SoftwareRoutePlanner
{
    private Dictionary<string, HashSet<(int Pid, long Created)>> previousMembership = [];
    public static string Fingerprint(SoftwareRule rule) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        $"{rule.ProcessName.Trim().ToUpperInvariant()}|{rule.ExecutablePath?.Trim().ToUpperInvariant()}|{rule.IncludeSubprocesses}|{rule.Mode}")));
    public static bool IsPublicIpv4(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address) || address.AddressFamily != AddressFamily.InterNetwork) return false;
        var b = address.GetAddressBytes();
        return b[0] != 0 && b[0] != 10 && b[0] != 127 && b[0] < 224
            && !(b[0] == 100 && b[1] is >= 64 and <= 127)
            && !(b[0] == 169 && b[1] == 254) && !(b[0] == 172 && b[1] is >= 16 and <= 31)
            && !(b[0] == 192 && (b[1] == 168 || (b[1] == 0 && b[2] is 0 or 2)))
            && !(b[0] == 198 && (b[1] is 18 or 19 || b[1] == 51 && b[2] == 100))
            && !(b[0] == 203 && b[1] == 0 && b[2] == 113);
    }
    public SoftwareObservation Observe(IEnumerable<SoftwareRule> rules, IEnumerable<SoftwareLearnedDestinations> learned, SoftwareConnectionSnapshot snapshot, IEnumerable<string> excluded)
    {
        var excludedSet = excluded.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var old = learned.GroupBy(l => l.Fingerprint).ToDictionary(g => g.Key, g => g.SelectMany(l => l.IpAddresses));
        var processes = snapshot.Processes.ToDictionary(p => p.ProcessId);
        var nextMembership = new Dictionary<string, HashSet<(int, long)>>();
        var result = new List<SoftwareLearnedDestinations>(); var counts = new Dictionary<string, int>();
        foreach (var rule in rules.Where(r => r.Enabled && r.Mode == DomainRouteMode.UseWireGuard).DistinctBy(Fingerprint))
        {
            var key = Fingerprint(rule);
            var roots = processes.Values.Where(p => Matches(rule, p)).Select(p => p.ProcessId).ToHashSet();
            previousMembership.TryGetValue(key, out var retained);
            var members = new HashSet<(int, long)>();
            foreach (var process in processes.Values)
            {
                var identity = (process.ProcessId, process.CreationTime);
                var matches = roots.Contains(process.ProcessId);
                if (!matches && rule.IncludeSubprocesses)
                {
                    matches = retained?.Contains(identity) == true;
                    var current = process; var seen = new HashSet<int> { current.ProcessId };
                    while (!matches && processes.TryGetValue(current.ParentProcessId, out var parent)
                        && parent.CreationTime <= current.CreationTime && seen.Add(parent.ProcessId))
                    {
                        matches = roots.Contains(parent.ProcessId) || retained?.Contains((parent.ProcessId, parent.CreationTime)) == true;
                        current = parent;
                    }
                }
                if (matches) members.Add(identity);
            }
            nextMembership[key] = members;
            var ids = members.Select(m => m.Item1).ToHashSet();
            var addresses = old.GetValueOrDefault(key, []).Concat(snapshot.Connections.Where(c => ids.Contains(c.ProcessId)).Select(c => c.RemoteAddress))
                .Where(ip => IsPublicIpv4(ip) && !excludedSet.Any(exclusion => IsInNetwork(ip, exclusion))).Distinct(StringComparer.OrdinalIgnoreCase).Order().ToList();
            result.Add(new(key, addresses)); counts[key] = ids.Count(id => !roots.Contains(id));
        }
        previousMembership = nextMembership;
        return new(result, counts);
    }
    private static bool IsInNetwork(string ip, string exclusion)
    {
        var parts = exclusion.Split('/');
        if (parts.Length == 1) return string.Equals(ip, exclusion, StringComparison.OrdinalIgnoreCase);
        if (parts.Length != 2 || !int.TryParse(parts[1], out var prefix) || prefix is < 0 or > 32
            || !IPAddress.TryParse(parts[0], out var network) || network.AddressFamily != AddressFamily.InterNetwork
            || !IPAddress.TryParse(ip, out var address) || address.AddressFamily != AddressFamily.InterNetwork) return false;
        var left = address.GetAddressBytes(); var right = network.GetAddressBytes();
        for (var i = 0; i < 4; i++)
        {
            var bits = Math.Clamp(prefix - i * 8, 0, 8); var mask = (byte)(0xff << (8 - bits));
            if ((left[i] & mask) != (right[i] & mask)) return false;
        }
        return true;
    }
    private static bool Matches(SoftwareRule rule, SoftwareProcess process) => !string.IsNullOrWhiteSpace(rule.ExecutablePath)
        ? string.Equals(rule.ExecutablePath.Trim(), process.ExecutablePath, StringComparison.OrdinalIgnoreCase)
        : string.Equals(rule.ProcessName, process.ExecutablePath.Replace('\\','/').Split('/').Last(), StringComparison.OrdinalIgnoreCase);
}

public interface ISoftwareRouteWriter
{
    // True only when this operation created the route. A pre-existing route is never adopted.
    Task<bool> EnsureAsync(SoftwareOwnedRoute route, CancellationToken cancellationToken);
    Task DeleteAsync(SoftwareOwnedRoute route, CancellationToken cancellationToken);
}
public sealed class SoftwareRouteReconciler(ISoftwareRouteWriter writer)
{
    public async Task ReconcileAsync(IEnumerable<string> desired, IEnumerable<string> domainIps, int? interfaceIndex,
        List<SoftwareOwnedRoute> owned, Action save, Func<bool> isCurrent, CancellationToken cancellationToken)
    {
        var wanted = desired.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var domains = domainIps.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (interfaceIndex is not null)
        {
            // Domain overlap protects an IP on the selected interface, not a stale route
            // on a different still-running tunnel. Install replacement before cleanup.
            wanted.UnionWith(domains.Where(ip => owned.Any(r => r.IpAddress == ip && r.InterfaceIndex != interfaceIndex)));
            foreach (var ip in wanted)
            {
                cancellationToken.ThrowIfCancellationRequested(); if (!isCurrent()) return;
                var route = new SoftwareOwnedRoute(ip, interfaceIndex.Value, "0.0.0.0", 3);
                if (await writer.EnsureAsync(route, cancellationToken) && !owned.Contains(route))
                {
                    owned.Add(route); save();
                }
            }
        }
        foreach (var route in owned.ToArray())
        {
            cancellationToken.ThrowIfCancellationRequested(); if (!isCurrent()) return;
            if ((domains.Contains(route.IpAddress) || wanted.Contains(route.IpAddress))
                && (interfaceIndex is null || route.InterfaceIndex == interfaceIndex)) continue;
            await writer.DeleteAsync(route, cancellationToken);
            owned.Remove(route); save(); // Only a confirmed deletion retires cleanup debt.
        }
    }
}
