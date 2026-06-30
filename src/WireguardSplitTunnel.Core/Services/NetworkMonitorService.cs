using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public interface INetworkMonitorService
{
    Task<NetworkMonitorSnapshot> CaptureAsync(
        AppState state,
        string? wireGuardInterfaceName,
        CancellationToken cancellationToken);
}

public sealed record NetworkAdapterSample(
    string Name,
    string Description,
    int InterfaceIndex,
    bool IsAvailable,
    long BytesReceived,
    long BytesSent,
    IReadOnlyList<string> Ipv4Addresses,
    IReadOnlyList<string>? GatewayAddresses = null);

public sealed record NetworkRouteEntry(string Destination, string Netmask, string InterfaceIp, int Metric);

public sealed record NetworkConnection(int ProcessId, IPAddress RemoteAddress, int RemotePort);

public sealed record NetworkProcessIdentity(int ProcessId, string ProcessName, string? ExecutablePath, string? Warning);

public sealed record NetworkPingProbeResult(bool Success, double? RoundTripMs, bool TimedOut, double PacketLossPercent);

public sealed record NetworkLatencySample(DateTimeOffset CapturedAt, bool Success, double? RoundTripMs);

public sealed record NetworkGraphSample(DateTimeOffset CapturedAt, double VpnMbps, double NormalMbps);

public sealed record NetworkGraphPoint(double X, double Y);

public static class NetworkPingOutputParser
{
    private static readonly Regex TimeRegex = new(@"(?:time|時間)\s*(?<op>[=<])\s*(?<value>\d+(?:\.\d+)?)\s*ms", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex LossRegex = new(@"\((?<loss>\d+(?:\.\d+)?)%\s*(?:loss|遺失)\)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex MacLossRegex = new(@"(?<loss>\d+(?:\.\d+)?)%\s*packet\s+loss", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static NetworkPingProbeResult Parse(string output, int exitCode)
    {
        var timeMatch = TimeRegex.Match(output);
        var lossPercent = ParseLoss(output);
        if (timeMatch.Success && double.TryParse(timeMatch.Groups["value"].Value, out var roundTrip))
        {
            if (timeMatch.Groups["op"].Value == "<" && roundTrip <= 1)
            {
                roundTrip = 0.5;
            }

            return new NetworkPingProbeResult(true, roundTrip, false, lossPercent ?? 0);
        }

        var timedOut = exitCode != 0
            || output.Contains("timed out", StringComparison.OrdinalIgnoreCase)
            || output.Contains("timeout", StringComparison.OrdinalIgnoreCase)
            || output.Contains("逾時", StringComparison.OrdinalIgnoreCase);
        return new NetworkPingProbeResult(false, null, timedOut, lossPercent ?? 100);
    }

    private static double? ParseLoss(string output)
    {
        var match = LossRegex.Match(output);
        if (!match.Success)
        {
            match = MacLossRegex.Match(output);
        }

        return match.Success && double.TryParse(match.Groups["loss"].Value, out var loss)
            ? loss
            : null;
    }
}

public sealed class NetworkLatencyWindow
{
    private const int MaxSamples = 5;
    private readonly Queue<NetworkLatencySample> samples = new();

    public NetworkLatencyWindow(string name, string target)
    {
        Name = name;
        Target = target;
    }

    public string Name { get; }

    public string Target { get; }

    public void Add(NetworkPingProbeResult result, DateTimeOffset capturedAt)
    {
        samples.Enqueue(new NetworkLatencySample(capturedAt, result.Success, result.RoundTripMs));
        while (samples.Count > MaxSamples)
        {
            samples.Dequeue();
        }
    }

    public NetworkLatencySummary GetSummary(DateTimeOffset capturedAt, string? targetOverride = null)
    {
        if (samples.Count == 0)
        {
            return Unavailable(Name, targetOverride ?? Target);
        }

        var sampleArray = samples.ToArray();
        var successful = sampleArray
            .Where(sample => sample.Success && sample.RoundTripMs.HasValue)
            .ToArray();
        var latestSuccess = successful.LastOrDefault();
        var packetLoss = sampleArray.Count(sample => !sample.Success) * 100d / sampleArray.Length;
        var jitter = CalculateJitter(successful);
        var latest = sampleArray[^1];
        var status = latest.Success ? "OK" : "Timeout";

        return new NetworkLatencySummary(
            Name,
            targetOverride ?? Target,
            true,
            latestSuccess?.RoundTripMs,
            jitter,
            packetLoss,
            latest.CapturedAt,
            status);
    }

    public static NetworkLatencySummary Unavailable(string name, string target) =>
        new(name, target, false, null, null, 0, null, "Unavailable");

    private static double? CalculateJitter(IReadOnlyList<NetworkLatencySample> successful)
    {
        if (successful.Count < 2)
        {
            return null;
        }

        var deltas = new List<double>();
        for (var i = 1; i < successful.Count; i++)
        {
            deltas.Add(Math.Abs(successful[i].RoundTripMs!.Value - successful[i - 1].RoundTripMs!.Value));
        }

        return deltas.Average();
    }
}

public sealed class NetworkGraphHistory
{
    private readonly TimeSpan window;
    private readonly List<NetworkGraphSample> samples = [];

    public NetworkGraphHistory(TimeSpan window)
    {
        this.window = window;
    }

    public IReadOnlyList<NetworkGraphSample> Samples => samples;

    public void Add(NetworkGraphSample sample)
    {
        samples.Add(sample);
        var cutoff = sample.CapturedAt - window;
        samples.RemoveAll(item => item.CapturedAt < cutoff);
    }

    public double GetPeakMbps(bool useVpn)
    {
        return samples.Count == 0
            ? 0
            : samples.Max(sample => useVpn ? sample.VpnMbps : sample.NormalMbps);
    }

    public double GetAverageMbps(TimeSpan averageWindow, bool useVpn)
    {
        if (samples.Count == 0)
        {
            return 0;
        }

        var cutoff = samples[^1].CapturedAt - averageWindow;
        var inWindow = samples.Where(sample => sample.CapturedAt >= cutoff).ToArray();
        return inWindow.Length == 0
            ? 0
            : inWindow.Average(sample => useVpn ? sample.VpnMbps : sample.NormalMbps);
    }
}

public static class NetworkGraphNormalizer
{
    public static IReadOnlyList<NetworkGraphPoint> Normalize(
        IReadOnlyList<NetworkGraphSample> samples,
        double width,
        double height,
        bool useVpn)
    {
        if (samples.Count == 0)
        {
            return [];
        }

        var values = samples.Select(sample => useVpn ? sample.VpnMbps : sample.NormalMbps).ToArray();
        var max = values.Max();
        var safeWidth = Math.Max(0, width);
        var safeHeight = Math.Max(0, height);
        var denominator = Math.Max(1, samples.Count - 1);

        return values
            .Select((value, index) =>
            {
                var x = samples.Count == 1 ? safeWidth : safeWidth * index / denominator;
                var y = max <= 0 ? safeHeight : safeHeight - (safeHeight * value / max);
                return new NetworkGraphPoint(x, Math.Clamp(y, 0, safeHeight));
            })
            .ToArray();
    }
}

public sealed class NetworkTrafficCalculator
{
    private readonly Dictionary<string, PreviousTrafficSample> previousSamples = new(StringComparer.OrdinalIgnoreCase);

    public NetworkTrafficSummary Calculate(NetworkAdapterSample sample, DateTimeOffset capturedAt)
    {
        var downloadBytesPerSecond = 0d;
        var uploadBytesPerSecond = 0d;

        if (previousSamples.TryGetValue(sample.Name, out var previous))
        {
            var elapsedSeconds = (capturedAt - previous.CapturedAt).TotalSeconds;
            if (elapsedSeconds > 0)
            {
                downloadBytesPerSecond = Math.Max(0, sample.BytesReceived - previous.BytesReceived) / elapsedSeconds;
                uploadBytesPerSecond = Math.Max(0, sample.BytesSent - previous.BytesSent) / elapsedSeconds;
            }
        }

        previousSamples[sample.Name] = new PreviousTrafficSample(sample.BytesReceived, sample.BytesSent, capturedAt);
        return new NetworkTrafficSummary(
            sample.Name,
            sample.Description,
            sample.IsAvailable,
            sample.BytesReceived,
            sample.BytesSent,
            downloadBytesPerSecond,
            uploadBytesPerSecond);
    }

    private sealed record PreviousTrafficSample(long BytesReceived, long BytesSent, DateTimeOffset CapturedAt);
}

public static class NetworkRouteClassifier
{
    public static NetworkRouteEntry? FindBestRoute(IPAddress remoteAddress, IEnumerable<NetworkRouteEntry> routes)
    {
        if (remoteAddress.AddressFamily != AddressFamily.InterNetwork)
        {
            return null;
        }

        var remote = ToUInt32(remoteAddress);
        return routes
            .Select(route => new RouteCandidate(route, PrefixLengthFromMask(route.Netmask)))
            .Where(candidate => candidate.PrefixLength >= 0
                && IPAddress.TryParse(candidate.Route.Destination, out _)
                && Matches(remote, candidate.Route.Destination, candidate.PrefixLength))
            .OrderByDescending(candidate => candidate.PrefixLength)
            .ThenBy(candidate => candidate.Route.Metric)
            .Select(candidate => candidate.Route)
            .FirstOrDefault();
    }

    public static NetworkPathKind Classify(
        IPAddress remoteAddress,
        IEnumerable<NetworkRouteEntry> routes,
        IEnumerable<string> wireGuardIpv4Addresses)
    {
        var bestRoute = FindBestRoute(remoteAddress, routes);
        if (bestRoute is null)
        {
            return NetworkPathKind.Unknown;
        }

        var wireGuardIps = wireGuardIpv4Addresses.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return wireGuardIps.Contains(bestRoute.InterfaceIp)
            ? NetworkPathKind.Vpn
            : NetworkPathKind.Normal;
    }

    private static bool Matches(uint remote, string destination, int prefixLength)
    {
        if (!IPAddress.TryParse(destination, out var destinationAddress)
            || destinationAddress.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        if (prefixLength == 0)
        {
            return true;
        }

        var mask = uint.MaxValue << (32 - prefixLength);
        return (remote & mask) == (ToUInt32(destinationAddress) & mask);
    }

    private static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return BitConverter.ToUInt32(bytes, 0);
    }

    private static int PrefixLengthFromMask(string netmask)
    {
        return netmask switch
        {
            "255.255.255.255" => 32,
            "255.255.255.254" => 31,
            "255.255.255.252" => 30,
            "255.255.255.248" => 29,
            "255.255.255.240" => 28,
            "255.255.255.224" => 27,
            "255.255.255.192" => 26,
            "255.255.255.128" => 25,
            "255.255.255.0" => 24,
            "255.255.254.0" => 23,
            "255.255.252.0" => 22,
            "255.255.248.0" => 21,
            "255.255.240.0" => 20,
            "255.255.224.0" => 19,
            "255.255.192.0" => 18,
            "255.255.128.0" => 17,
            "255.255.0.0" => 16,
            "255.254.0.0" => 15,
            "255.252.0.0" => 14,
            "255.248.0.0" => 13,
            "255.240.0.0" => 12,
            "255.224.0.0" => 11,
            "255.192.0.0" => 10,
            "255.128.0.0" => 9,
            "255.0.0.0" => 8,
            "254.0.0.0" => 7,
            "252.0.0.0" => 6,
            "248.0.0.0" => 5,
            "240.0.0.0" => 4,
            "224.0.0.0" => 3,
            "192.0.0.0" => 2,
            "128.0.0.0" => 1,
            "0.0.0.0" => 0,
            _ => -1
        };
    }

    private sealed record RouteCandidate(NetworkRouteEntry Route, int PrefixLength);
}

public static class NetstatTcpConnectionParser
{
    public static IReadOnlyList<NetworkConnection> Parse(string output)
    {
        var connections = new List<NetworkConnection>();
        foreach (var rawLine in output.Split(["\r\n", "\n"], StringSplitOptions.None))
        {
            var parts = rawLine.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5 || !string.Equals(parts[0], "TCP", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var state = parts[^2];
            var pidToken = parts[^1];
            var remoteToken = parts[2];
            if (!string.Equals(state, "ESTABLISHED", StringComparison.OrdinalIgnoreCase)
                || !int.TryParse(pidToken, out var pid)
                || !TryParseEndpoint(remoteToken, out var address, out var port))
            {
                continue;
            }

            connections.Add(new NetworkConnection(pid, address, port));
        }

        return connections;
    }

    private static bool TryParseEndpoint(string endpoint, out IPAddress address, out int port)
    {
        address = IPAddress.None;
        port = 0;

        if (endpoint.StartsWith("[", StringComparison.Ordinal))
        {
            var endBracket = endpoint.IndexOf("]:", StringComparison.Ordinal);
            if (endBracket <= 1)
            {
                return false;
            }

            var addressText = endpoint[1..endBracket];
            var portText = endpoint[(endBracket + 2)..];
            return IPAddress.TryParse(addressText, out address!) && int.TryParse(portText, out port);
        }

        var separator = endpoint.LastIndexOf(':');
        if (separator <= 0 || separator == endpoint.Length - 1)
        {
            return false;
        }

        return IPAddress.TryParse(endpoint[..separator], out address!) && int.TryParse(endpoint[(separator + 1)..], out port);
    }
}

public sealed class NetworkDomainMatcher
{
    private readonly Dictionary<string, string> domainsByIp;

    private NetworkDomainMatcher(Dictionary<string, string> domainsByIp)
    {
        this.domainsByIp = domainsByIp;
    }

    public static NetworkDomainMatcher FromState(AppState state)
    {
        var domainsByIp = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in state.ManagedRouteSnapshot)
        {
            if (!string.IsNullOrWhiteSpace(entry.IpAddress) && !domainsByIp.ContainsKey(entry.IpAddress))
            {
                domainsByIp[entry.IpAddress] = entry.Domain;
            }
        }

        foreach (var (domain, ips) in state.LastKnownResolvedIps)
        {
            foreach (var ip in ips)
            {
                if (!string.IsNullOrWhiteSpace(ip) && !domainsByIp.ContainsKey(ip))
                {
                    domainsByIp[ip] = domain;
                }
            }
        }

        foreach (var (domain, details) in state.LastKnownResolvedIpDetails)
        {
            foreach (var detail in details)
            {
                if (!string.IsNullOrWhiteSpace(detail.IpAddress) && !domainsByIp.ContainsKey(detail.IpAddress))
                {
                    domainsByIp[detail.IpAddress] = domain;
                }
            }
        }

        return new NetworkDomainMatcher(domainsByIp);
    }

    public string ResolveDisplayName(IPAddress address, Func<IPAddress, string?>? fallbackResolver = null)
    {
        var key = address.ToString();
        if (domainsByIp.TryGetValue(key, out var domain))
        {
            return domain;
        }

        var fallback = fallbackResolver?.Invoke(address);
        return string.IsNullOrWhiteSpace(fallback) ? key : fallback;
    }
}

public static class NetworkActivityAggregator
{
    public static IReadOnlyList<NetworkActivityRow> BuildRows(
        IEnumerable<NetworkConnection> connections,
        Func<int, NetworkProcessIdentity> processResolver,
        Func<IPAddress, NetworkPathKind> routeClassifier,
        NetworkDomainMatcher domainMatcher,
        DateTimeOffset capturedAt,
        out IReadOnlyList<string> warnings)
    {
        return BuildRows(
            connections,
            processResolver,
            routeClassifier,
            address => domainMatcher.ResolveDisplayName(address),
            capturedAt,
            out warnings);
    }

    public static IReadOnlyList<NetworkActivityRow> BuildRows(
        IEnumerable<NetworkConnection> connections,
        Func<int, NetworkProcessIdentity> processResolver,
        Func<IPAddress, NetworkPathKind> routeClassifier,
        Func<IPAddress, string> domainResolver,
        DateTimeOffset capturedAt,
        out IReadOnlyList<string> warnings)
    {
        var warningSet = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var rows = connections
            .GroupBy(connection => new
            {
                connection.ProcessId,
                RemoteAddress = connection.RemoteAddress.ToString(),
                connection.RemotePort
            })
            .Select(group =>
            {
                var first = group.First();
                var identity = ResolveProcess(processResolver, first.ProcessId);
                if (!string.IsNullOrWhiteSpace(identity.Warning))
                {
                    warningSet.Add($"PID {identity.ProcessId} {identity.ProcessName}: {identity.Warning}");
                }

                var route = routeClassifier(first.RemoteAddress);
                var domain = domainResolver(first.RemoteAddress);
                return new NetworkActivityRow(
                    identity.ProcessName,
                    identity.ProcessId,
                    identity.ExecutablePath,
                    domain,
                    $"{first.RemoteAddress}:{first.RemotePort}",
                    route,
                    group.Count(),
                    capturedAt);
            })
            .OrderBy(row => row.Route == NetworkPathKind.Unknown ? 1 : 0)
            .ThenBy(row => row.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(row => row.DomainOrAddress, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        warnings = warningSet.ToArray();
        return rows;
    }

    private static NetworkProcessIdentity ResolveProcess(Func<int, NetworkProcessIdentity> processResolver, int processId)
    {
        try
        {
            return processResolver(processId);
        }
        catch (Exception ex)
        {
            return new NetworkProcessIdentity(processId, $"pid:{processId}", null, ex.Message);
        }
    }
}

public sealed class SystemNetworkMonitorService : INetworkMonitorService
{
    private const int MaxReverseDnsLookupsPerCapture = 8;
    private static readonly TimeSpan LatencySampleInterval = TimeSpan.FromSeconds(5);
    private readonly NetworkTrafficCalculator vpnTrafficCalculator = new();
    private readonly NetworkTrafficCalculator normalTrafficCalculator = new();
    private readonly NetworkLatencyWindow vpnLatencyWindow = new("VPN", "1.1.1.1");
    private readonly NetworkLatencyWindow normalLatencyWindow = new("Normal", "Gateway");
    private readonly Dictionary<string, string> reverseDnsCache = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset lastLatencySampleAt = DateTimeOffset.MinValue;

    public async Task<NetworkMonitorSnapshot> CaptureAsync(
        AppState state,
        string? wireGuardInterfaceName,
        CancellationToken cancellationToken)
    {
        var capturedAt = DateTimeOffset.Now;
        var warnings = new List<string>();
        var adapters = GetAdapterSamples(warnings);
        var wireGuardAdapter = FindWireGuardAdapter(adapters, wireGuardInterfaceName);
        var normalAdapter = BuildNormalAdapterSample(adapters, wireGuardAdapter?.Name);
        var vpnTraffic = wireGuardAdapter is null
            ? UnavailableTraffic("WireGuard")
            : vpnTrafficCalculator.Calculate(wireGuardAdapter, capturedAt);
        var normalTraffic = normalTrafficCalculator.Calculate(normalAdapter, capturedAt);
        var connections = await GetConnectionsAsync(warnings, cancellationToken);
        var matcher = NetworkDomainMatcher.FromState(state);
        var wireGuardIps = wireGuardAdapter?.Ipv4Addresses ?? [];
        var quality = await CaptureQualityAsync(wireGuardAdapter, normalAdapter, capturedAt, warnings, cancellationToken);
        var displayNames = await BuildDomainDisplayNamesAsync(connections, matcher, warnings, cancellationToken);
        var routeClassifier = await BuildRouteClassifierAsync(
            connections,
            wireGuardAdapter,
            wireGuardInterfaceName,
            wireGuardIps,
            warnings,
            cancellationToken);

        var rows = NetworkActivityAggregator.BuildRows(
            connections,
            ResolveProcessIdentity,
            routeClassifier,
            address => displayNames.TryGetValue(address.ToString(), out var display) ? display : address.ToString(),
            capturedAt,
            out var rowWarnings);

        warnings.AddRange(rowWarnings);
        return new NetworkMonitorSnapshot(
            capturedAt,
            wireGuardAdapter?.Name ?? wireGuardInterfaceName ?? string.Empty,
            wireGuardAdapter is not null,
            vpnTraffic,
            normalTraffic,
            quality,
            rows,
            warnings.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private async Task<NetworkQualitySnapshot> CaptureQualityAsync(
        NetworkAdapterSample? wireGuardAdapter,
        NetworkAdapterSample normalAdapter,
        DateTimeOffset capturedAt,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        if (capturedAt - lastLatencySampleAt < LatencySampleInterval)
        {
            return BuildQualitySnapshot(wireGuardAdapter, normalAdapter, capturedAt);
        }

        lastLatencySampleAt = capturedAt;
        var wireGuardSource = wireGuardAdapter?.Ipv4Addresses.FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(wireGuardSource))
        {
            var vpnProbe = await RunPingProbeAsync(
                NetworkPingCommandBuilder.BuildVpnArguments(wireGuardSource, OperatingSystem.IsMacOS()),
                warnings,
                cancellationToken);
            vpnLatencyWindow.Add(vpnProbe, capturedAt);
        }

        var normalGateway = normalAdapter.GatewayAddresses?.FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(normalGateway))
        {
            var normalProbe = await RunPingProbeAsync(
                NetworkPingCommandBuilder.BuildNormalArguments(normalGateway, OperatingSystem.IsMacOS()),
                warnings,
                cancellationToken);
            normalLatencyWindow.Add(normalProbe, capturedAt);
        }

        return BuildQualitySnapshot(wireGuardAdapter, normalAdapter, capturedAt);
    }

    private NetworkQualitySnapshot BuildQualitySnapshot(
        NetworkAdapterSample? wireGuardAdapter,
        NetworkAdapterSample normalAdapter,
        DateTimeOffset capturedAt)
    {
        var vpnSummary = wireGuardAdapter?.Ipv4Addresses.Count > 0
            ? vpnLatencyWindow.GetSummary(capturedAt, "1.1.1.1")
            : NetworkLatencyWindow.Unavailable("VPN", "1.1.1.1");
        var normalTarget = normalAdapter.GatewayAddresses?.FirstOrDefault() ?? "Gateway";
        var normalSummary = normalAdapter.IsAvailable && normalAdapter.GatewayAddresses?.Count > 0
            ? normalLatencyWindow.GetSummary(capturedAt, normalTarget)
            : NetworkLatencyWindow.Unavailable("Normal", normalTarget);

        return new NetworkQualitySnapshot(vpnSummary, normalSummary);
    }

    private static async Task<NetworkPingProbeResult> RunPingProbeAsync(
        string arguments,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await RunProcessCaptureAsync("ping", arguments, cancellationToken);
            return NetworkPingOutputParser.Parse(
                (result.Stdout + Environment.NewLine + result.Stderr).Trim(),
                result.ExitCode);
        }
        catch (Exception ex)
        {
            warnings.Add($"ping failed: {ex.Message}");
            return new NetworkPingProbeResult(false, null, true, 100);
        }
    }

    private async Task<Dictionary<string, string>> BuildDomainDisplayNamesAsync(
        IReadOnlyList<NetworkConnection> connections,
        NetworkDomainMatcher matcher,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var reverseLookupCount = 0;
        foreach (var address in connections.Select(connection => connection.RemoteAddress).Distinct())
        {
            var stateMatch = matcher.ResolveDisplayName(address);
            if (!string.Equals(stateMatch, address.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                result[address.ToString()] = stateMatch;
                continue;
            }

            if (reverseLookupCount >= MaxReverseDnsLookupsPerCapture)
            {
                result[address.ToString()] = address.ToString();
                continue;
            }

            reverseLookupCount++;
            result[address.ToString()] = await ResolveReverseDnsAsync(address, warnings, cancellationToken)
                ?? address.ToString();
        }

        return result;
    }

    private async Task<string?> ResolveReverseDnsAsync(IPAddress address, List<string> warnings, CancellationToken cancellationToken)
    {
        var key = address.ToString();
        if (reverseDnsCache.TryGetValue(key, out var cached))
        {
            return cached;
        }

        try
        {
            var entry = await Dns.GetHostEntryAsync(address.ToString())
                .WaitAsync(TimeSpan.FromMilliseconds(300), cancellationToken);
            if (!string.IsNullOrWhiteSpace(entry.HostName))
            {
                reverseDnsCache[key] = entry.HostName;
                return entry.HostName;
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            warnings.Add($"Reverse DNS timed out for {key}.");
        }
        catch (Exception)
        {
            // Reverse DNS is best-effort; the IP address remains useful.
        }

        return null;
    }

    private static IReadOnlyList<NetworkAdapterSample> GetAdapterSamples(List<string> warnings)
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(adapter => adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(ToSample)
                .ToArray();
        }
        catch (Exception ex)
        {
            warnings.Add($"Unable to read network adapters: {ex.Message}");
            return [];
        }
    }

    private static NetworkAdapterSample ToSample(NetworkInterface adapter)
    {
        var ipv4 = adapter.GetIPProperties().UnicastAddresses
            .Where(address => address.Address.AddressFamily == AddressFamily.InterNetwork)
            .Select(address => address.Address.ToString())
            .ToArray();
        var gateways = adapter.GetIPProperties().GatewayAddresses
            .Select(gateway => gateway.Address)
            .Where(address => address.AddressFamily == AddressFamily.InterNetwork
                && !IPAddress.Any.Equals(address)
                && !IPAddress.None.Equals(address))
            .Select(address => address.ToString())
            .ToArray();
        var statistics = adapter.GetIPStatistics();
        var properties = adapter.GetIPProperties().GetIPv4Properties();
        return new NetworkAdapterSample(
            adapter.Name,
            adapter.Description,
            properties?.Index ?? -1,
            adapter.OperationalStatus == OperationalStatus.Up,
            statistics.BytesReceived,
            statistics.BytesSent,
            ipv4,
            gateways);
    }

    private static NetworkAdapterSample? FindWireGuardAdapter(
        IReadOnlyList<NetworkAdapterSample> adapters,
        string? preferredName)
    {
        if (!string.IsNullOrWhiteSpace(preferredName))
        {
            var preferred = adapters.FirstOrDefault(adapter =>
                adapter.IsAvailable
                && (string.Equals(adapter.Name, preferredName, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(adapter.Description, preferredName, StringComparison.OrdinalIgnoreCase)));
            if (preferred is not null)
            {
                return preferred;
            }
        }

        return adapters.FirstOrDefault(adapter =>
            adapter.IsAvailable
            && (adapter.Name.Contains("wireguard", StringComparison.OrdinalIgnoreCase)
                || adapter.Description.Contains("wireguard", StringComparison.OrdinalIgnoreCase)
                || (OperatingSystem.IsMacOS() && adapter.Name.StartsWith("utun", StringComparison.OrdinalIgnoreCase))));
    }

    private static NetworkAdapterSample BuildNormalAdapterSample(
        IReadOnlyList<NetworkAdapterSample> adapters,
        string? wireGuardInterfaceName)
    {
        var normalAdapters = adapters
            .Where(adapter => adapter.IsAvailable)
            .Where(adapter => string.IsNullOrWhiteSpace(wireGuardInterfaceName)
                || !string.Equals(adapter.Name, wireGuardInterfaceName, StringComparison.OrdinalIgnoreCase))
            .Where(adapter => !adapter.Name.Contains("wireguard", StringComparison.OrdinalIgnoreCase)
                && !adapter.Description.Contains("wireguard", StringComparison.OrdinalIgnoreCase)
                && !(OperatingSystem.IsMacOS() && adapter.Name.StartsWith("utun", StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        return new NetworkAdapterSample(
            "Normal",
            normalAdapters.Length == 0
                ? "No active normal adapters"
                : string.Join(", ", normalAdapters.Select(adapter => adapter.Name)),
            -1,
            normalAdapters.Length > 0,
            normalAdapters.Sum(adapter => adapter.BytesReceived),
            normalAdapters.Sum(adapter => adapter.BytesSent),
            normalAdapters.SelectMany(adapter => adapter.Ipv4Addresses).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            normalAdapters.SelectMany(adapter => adapter.GatewayAddresses ?? []).Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private static NetworkTrafficSummary UnavailableTraffic(string name) =>
        new(name, string.Empty, false, 0, 0, 0, 0);

    private static async Task<IReadOnlyList<NetworkRouteEntry>> GetRoutesAsync(
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await RunProcessCaptureAsync("route", "print -4", cancellationToken);
            if (result.ExitCode != 0)
            {
                warnings.Add($"route print failed: {result.Stderr}");
                return [];
            }

            return ParseRoutePrint(result.Stdout);
        }
        catch (Exception ex)
        {
            warnings.Add($"Unable to read route table: {ex.Message}");
            return [];
        }
    }

    private static async Task<Func<IPAddress, NetworkPathKind>> BuildRouteClassifierAsync(
        IReadOnlyList<NetworkConnection> connections,
        NetworkAdapterSample? wireGuardAdapter,
        string? wireGuardInterfaceName,
        IReadOnlyList<string> wireGuardIps,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsMacOS())
        {
            var routeInterfaces = await GetMacRouteInterfacesAsync(connections, warnings, cancellationToken);
            var wireGuardName = wireGuardAdapter?.Name ?? wireGuardInterfaceName;
            return address => MacRouteGetParser.ClassifyInterface(
                routeInterfaces.TryGetValue(address.ToString(), out var routeInterface) ? routeInterface : null,
                wireGuardName);
        }

        var routes = await GetRoutesAsync(warnings, cancellationToken);
        return address => NetworkRouteClassifier.Classify(address, routes, wireGuardIps);
    }

    private static async Task<Dictionary<string, string>> GetMacRouteInterfacesAsync(
        IReadOnlyList<NetworkConnection> connections,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        var output = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var address in connections
            .Select(connection => connection.RemoteAddress)
            .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
            .Distinct()
            .Take(100))
        {
            try
            {
                var result = await RunProcessCaptureAsync("/sbin/route", $"-n get {address}", cancellationToken);
                if (result.ExitCode != 0)
                {
                    warnings.Add($"route get failed for {address}: {result.Stderr}");
                    continue;
                }

                var routeInterface = MacRouteGetParser.ParseInterface(result.Stdout);
                if (!string.IsNullOrWhiteSpace(routeInterface))
                {
                    output[address.ToString()] = routeInterface;
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Unable to classify route for {address}: {ex.Message}");
            }
        }

        return output;
    }

    private static IReadOnlyList<NetworkRouteEntry> ParseRoutePrint(string output)
    {
        var routes = new List<NetworkRouteEntry>();
        foreach (var rawLine in output.Split(["\r\n", "\n"], StringSplitOptions.None))
        {
            var parts = rawLine.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5
                || !IPAddress.TryParse(parts[0], out _)
                || !IPAddress.TryParse(parts[1], out _)
                || !IPAddress.TryParse(parts[3], out _)
                || !int.TryParse(parts[4], out var metric))
            {
                continue;
            }

            routes.Add(new NetworkRouteEntry(parts[0], parts[1], parts[3], metric));
        }

        return routes;
    }

    private static async Task<IReadOnlyList<NetworkConnection>> GetConnectionsAsync(
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        try
        {
            if (OperatingSystem.IsMacOS())
            {
                var macResult = await RunProcessCaptureAsync(ResolveMacLsofPath(), "-nP -iTCP -sTCP:ESTABLISHED", cancellationToken);
                var parsed = MacLsofResultParser.Parse(macResult.ExitCode, macResult.Stdout, macResult.Stderr);
                if (!string.IsNullOrWhiteSpace(parsed.Warning))
                {
                    warnings.Add(parsed.Warning);
                }

                return parsed.Connections;
            }

            var result = await RunProcessCaptureAsync("netstat", "-ano", cancellationToken);
            if (result.ExitCode != 0)
            {
                warnings.Add($"netstat failed: {result.Stderr}");
                return [];
            }

            return NetstatTcpConnectionParser.Parse(result.Stdout);
        }
        catch (Exception ex)
        {
            warnings.Add($"Unable to read active connections: {ex.Message}");
            return [];
        }
    }

    private static string ResolveMacLsofPath() =>
        File.Exists("/usr/sbin/lsof") ? "/usr/sbin/lsof" : "lsof";

    private static NetworkProcessIdentity ResolveProcessIdentity(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            var processName = string.IsNullOrWhiteSpace(process.ProcessName)
                ? $"pid:{processId}"
                : OperatingSystem.IsWindows() && !process.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? $"{process.ProcessName}.exe"
                    : process.ProcessName;

            try
            {
                return new NetworkProcessIdentity(processId, processName, process.MainModule?.FileName, null);
            }
            catch (Exception ex)
            {
                return new NetworkProcessIdentity(processId, processName, null, ex.Message);
            }
        }
        catch (Exception ex)
        {
            return new NetworkProcessIdentity(processId, $"pid:{processId}", null, ex.Message);
        }
    }

    private static async Task<ProcessCaptureResult> RunProcessCaptureAsync(
        string fileName,
        string arguments,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Unable to start process: {fileName} {arguments}");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        return new ProcessCaptureResult(
            process.ExitCode,
            (await stdoutTask).Trim(),
            (await stderrTask).Trim());
    }

    private sealed record ProcessCaptureResult(int ExitCode, string Stdout, string Stderr);
}
