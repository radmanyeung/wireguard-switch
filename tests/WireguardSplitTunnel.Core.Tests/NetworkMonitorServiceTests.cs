using System.Net;
using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class NetworkMonitorServiceTests
{
    [Fact]
    public void TrafficCalculator_FirstSample_ReturnsZeroSpeed()
    {
        var calculator = new NetworkTrafficCalculator();
        var sample = new NetworkAdapterSample("nordusa1", "WireGuard Tunnel", 7, true, 1_000, 2_000, ["10.5.0.2"]);

        var summary = calculator.Calculate(sample, DateTimeOffset.Parse("2026-06-15T10:00:00Z"));

        summary.DownloadBytesPerSecond.Should().Be(0);
        summary.UploadBytesPerSecond.Should().Be(0);
        summary.BytesReceived.Should().Be(1_000);
        summary.BytesSent.Should().Be(2_000);
    }

    [Fact]
    public void TrafficCalculator_CounterReset_DoesNotReturnNegativeSpeed()
    {
        var calculator = new NetworkTrafficCalculator();
        var first = new NetworkAdapterSample("nordusa1", "WireGuard Tunnel", 7, true, 5_000, 6_000, ["10.5.0.2"]);
        var reset = new NetworkAdapterSample("nordusa1", "WireGuard Tunnel", 7, true, 100, 200, ["10.5.0.2"]);
        var start = DateTimeOffset.Parse("2026-06-15T10:00:00Z");

        calculator.Calculate(first, start);
        var summary = calculator.Calculate(reset, start.AddSeconds(1));

        summary.DownloadBytesPerSecond.Should().Be(0);
        summary.UploadBytesPerSecond.Should().Be(0);
    }

    [Fact]
    public void RouteClassifier_UsesLongestPrefixBeforeMetric()
    {
        var routes = new[]
        {
            new NetworkRouteEntry("0.0.0.0", "0.0.0.0", "192.168.68.22", 5),
            new NetworkRouteEntry("104.18.0.0", "255.255.0.0", "10.5.0.2", 50)
        };

        var route = NetworkRouteClassifier.FindBestRoute(
            IPAddress.Parse("104.18.32.47"),
            routes);

        route.Should().NotBeNull();
        route!.InterfaceIp.Should().Be("10.5.0.2");
    }

    [Fact]
    public void RouteClassifier_UsesMetricWhenPrefixTies()
    {
        var routes = new[]
        {
            new NetworkRouteEntry("104.18.32.0", "255.255.255.0", "10.5.0.2", 40),
            new NetworkRouteEntry("104.18.32.0", "255.255.255.0", "192.168.68.22", 10)
        };

        var kind = NetworkRouteClassifier.Classify(
            IPAddress.Parse("104.18.32.47"),
            routes,
            wireGuardIpv4Addresses: ["10.5.0.2"]);

        kind.Should().Be(NetworkPathKind.Normal);
    }

    [Fact]
    public void NetstatParser_ParsesIpv4AndIpv6EstablishedTcpRows()
    {
        const string output = """
          Proto  Local Address          Foreign Address        State           PID
          TCP    192.168.68.22:55123    104.18.32.47:443      ESTABLISHED     1234
          TCP    [::1]:55124            [2606:4700::6812:202f]:443  ESTABLISHED     5678
          UDP    0.0.0.0:5353           *:*                                    9999
          TCP    192.168.68.22:55125    203.0.113.10:443      TIME_WAIT       2222
        """;

        var rows = NetstatTcpConnectionParser.Parse(output);

        rows.Should().HaveCount(2);
        rows[0].ProcessId.Should().Be(1234);
        rows[0].RemoteAddress.Should().Be(IPAddress.Parse("104.18.32.47"));
        rows[0].RemotePort.Should().Be(443);
        rows[1].ProcessId.Should().Be(5678);
        rows[1].RemoteAddress.Should().Be(IPAddress.Parse("2606:4700::6812:202f"));
    }

    [Fact]
    public void MacLsofParser_ParsesEstablishedTcpRows()
    {
        const string output = """
        COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
        Safari   123 user   42u  IPv4 0x123456789      0t0  TCP 192.168.1.20:53124->104.18.32.47:443 (ESTABLISHED)
        Codex    456 user   18u  IPv4 0x987654321      0t0  TCP 10.5.0.2:52228->172.64.155.209:443 (ESTABLISHED)
        Mail     789 user   21u  IPv6 0x987654322      0t0  TCP [fe80::1]:53125->[2606:4700::6812:202f]:443 (ESTABLISHED)
        Notes    790 user   12u  IPv4 0x987654323      0t0  TCP 192.168.1.20:52229->203.0.113.1:443 (CLOSE_WAIT)
        """;

        var rows = MacLsofTcpConnectionParser.Parse(output);

        rows.Should().HaveCount(3);
        rows[0].ProcessId.Should().Be(123);
        rows[0].RemoteAddress.Should().Be(IPAddress.Parse("104.18.32.47"));
        rows[0].RemotePort.Should().Be(443);
        rows[1].ProcessId.Should().Be(456);
        rows[1].RemoteAddress.Should().Be(IPAddress.Parse("172.64.155.209"));
        rows[2].ProcessId.Should().Be(789);
        rows[2].RemoteAddress.Should().Be(IPAddress.Parse("2606:4700::6812:202f"));
    }

    [Fact]
    public void MacRouteGetParser_ParsesInterfaceAndClassifiesAgainstWireGuardInterface()
    {
        const string vpnRoute = """
           route to: 104.18.32.47
        destination: 104.18.32.47
          interface: utun5
        """;
        const string normalRoute = """
           route to: 8.8.8.8
        destination: default
           gateway: 192.168.1.1
          interface: en0
        """;

        MacRouteGetParser.ParseInterface(vpnRoute).Should().Be("utun5");
        MacRouteGetParser.ParseInterface(normalRoute).Should().Be("en0");
        MacRouteGetParser.ClassifyInterface("utun5", "utun5").Should().Be(NetworkPathKind.Vpn);
        MacRouteGetParser.ClassifyInterface("en0", "utun5").Should().Be(NetworkPathKind.Normal);
        MacRouteGetParser.ClassifyInterface(null, "utun5").Should().Be(NetworkPathKind.Unknown);
    }

    [Fact]
    public void DomainMatcher_UsesManagedRouteBeforeResolvedIp_ThenFallsBackToIp()
    {
        var state = new AppState(
            [new DomainRule("*.openai.com")],
            new Dictionary<string, List<string>>
            {
                ["*.openai.com"] = ["104.18.32.47"],
                ["older.example.com"] = ["104.18.32.48"]
            },
            [new ManagedRouteEntry("api.openai.com", "104.18.32.48")]);

        var matcher = NetworkDomainMatcher.FromState(state);

        matcher.ResolveDisplayName(IPAddress.Parse("104.18.32.48")).Should().Be("api.openai.com");
        matcher.ResolveDisplayName(IPAddress.Parse("104.18.32.47")).Should().Be("*.openai.com");
        matcher.ResolveDisplayName(IPAddress.Parse("203.0.113.10")).Should().Be("203.0.113.10");
    }

    [Fact]
    public void ActivityAggregator_AllowsProcessesWithoutReadableExecutablePath()
    {
        var connections = new[]
        {
            new NetworkConnection(42, IPAddress.Parse("104.18.32.47"), 443)
        };
        var processes = new Dictionary<int, NetworkProcessIdentity>
        {
            [42] = new(42, "protected.exe", null, "Access denied")
        };
        var matcher = NetworkDomainMatcher.FromState(new AppState([], new Dictionary<string, List<string>>(), []));

        var rows = NetworkActivityAggregator.BuildRows(
            connections,
            pid => processes[pid],
            _ => NetworkPathKind.Unknown,
            matcher,
            DateTimeOffset.Parse("2026-06-15T10:00:00Z"),
            out var warnings);

        rows.Should().ContainSingle();
        rows[0].ProcessName.Should().Be("protected.exe");
        rows[0].ExecutablePath.Should().BeNull();
        rows[0].DomainOrAddress.Should().Be("104.18.32.47");
        warnings.Should().ContainSingle().Which.Should().Contain("Access denied");
    }

    [Fact]
    public void PingOutputParser_ParsesSuccessfulTimeAndTimeout()
    {
        var success = NetworkPingOutputParser.Parse(
            "Reply from 1.1.1.1: bytes=32 time=24ms TTL=56",
            exitCode: 0);
        var timeout = NetworkPingOutputParser.Parse(
            "Request timed out.\r\nPackets: Sent = 1, Received = 0, Lost = 1 (100% loss)",
            exitCode: 1);

        success.Success.Should().BeTrue();
        success.RoundTripMs.Should().Be(24);
        success.PacketLossPercent.Should().Be(0);
        timeout.Success.Should().BeFalse();
        timeout.TimedOut.Should().BeTrue();
        timeout.PacketLossPercent.Should().Be(100);
    }

    [Fact]
    public void PingOutputParser_ParsesMacOutputAndCommandBuilderUsesPlatformArguments()
    {
        var success = NetworkPingOutputParser.Parse(
            "64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.345 ms\n--- 1.1.1.1 ping statistics ---\n1 packets transmitted, 1 packets received, 0.0% packet loss",
            exitCode: 0);
        var timeout = NetworkPingOutputParser.Parse(
            "--- 1.1.1.1 ping statistics ---\n1 packets transmitted, 0 packets received, 100.0% packet loss",
            exitCode: 2);

        success.Success.Should().BeTrue();
        success.RoundTripMs.Should().BeApproximately(12.345, 0.001);
        success.PacketLossPercent.Should().Be(0);
        timeout.Success.Should().BeFalse();
        timeout.PacketLossPercent.Should().Be(100);
        NetworkPingCommandBuilder.BuildVpnArguments("10.5.0.2", isMacOs: true).Should().Be("-S 10.5.0.2 -c 1 -W 1000 1.1.1.1");
        NetworkPingCommandBuilder.BuildNormalArguments("192.168.1.1", isMacOs: true).Should().Be("-c 1 -W 1000 192.168.1.1");
        NetworkPingCommandBuilder.BuildVpnArguments("10.5.0.2", isMacOs: false).Should().Be("-S 10.5.0.2 -n 1 -w 1000 1.1.1.1");
    }

    [Fact]
    public void LatencyWindow_ComputesLatestPingJitterAndLossFromLastFiveSamples()
    {
        var window = new NetworkLatencyWindow("VPN", "1.1.1.1");
        var start = DateTimeOffset.Parse("2026-06-15T10:00:00Z");

        window.Add(new NetworkPingProbeResult(true, 20, false, 0), start);
        window.Add(new NetworkPingProbeResult(true, 35, false, 0), start.AddSeconds(5));
        window.Add(new NetworkPingProbeResult(false, null, true, 100), start.AddSeconds(10));
        window.Add(new NetworkPingProbeResult(true, 25, false, 0), start.AddSeconds(15));
        window.Add(new NetworkPingProbeResult(false, null, true, 100), start.AddSeconds(20));
        window.Add(new NetworkPingProbeResult(true, 30, false, 0), start.AddSeconds(25));

        var summary = window.GetSummary(start.AddSeconds(25));

        summary.IsAvailable.Should().BeTrue();
        summary.PingMs.Should().Be(30);
        summary.JitterMs.Should().BeApproximately(7.5, 0.01);
        summary.PacketLossPercent.Should().Be(40);
    }

    [Fact]
    public void GraphHistory_KeepsLastSixtySecondsAndTracksPeakAndAverage()
    {
        var history = new NetworkGraphHistory(TimeSpan.FromSeconds(60));
        var start = DateTimeOffset.Parse("2026-06-15T10:00:00Z");

        history.Add(new NetworkGraphSample(start, VpnMbps: 1, NormalMbps: 2));
        history.Add(new NetworkGraphSample(start.AddSeconds(31), VpnMbps: 10, NormalMbps: 20));
        history.Add(new NetworkGraphSample(start.AddSeconds(61), VpnMbps: 4, NormalMbps: 8));

        history.Samples.Should().HaveCount(2);
        history.GetPeakMbps(useVpn: true).Should().Be(10);
        history.GetAverageMbps(TimeSpan.FromSeconds(30), useVpn: false).Should().Be(14);
    }

    [Fact]
    public void GraphNormalizer_HandlesZeroAndSinglePointWithoutInvalidCoordinates()
    {
        var zeroPoints = NetworkGraphNormalizer.Normalize(
            [new NetworkGraphSample(DateTimeOffset.Parse("2026-06-15T10:00:00Z"), 0, 0)],
            width: 100,
            height: 40,
            useVpn: true);
        var singlePeak = NetworkGraphNormalizer.Normalize(
            [new NetworkGraphSample(DateTimeOffset.Parse("2026-06-15T10:00:00Z"), 12, 0)],
            width: 100,
            height: 40,
            useVpn: true);

        zeroPoints.Should().ContainSingle();
        zeroPoints[0].Y.Should().Be(40);
        singlePeak.Should().ContainSingle();
        singlePeak[0].X.Should().Be(100);
        singlePeak[0].Y.Should().Be(0);
    }
}
