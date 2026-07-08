using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacSplitTunnelConfigServiceTests
{
    private const string NordConfig = """
        [Interface]
        PrivateKey = SECRETKEY=
        Address = 10.5.0.2/32
        DNS = 103.86.96.100, 103.86.99.100

        [Peer]
        PublicKey = U3dKnkOJY5P9p6kEbEDGR7+K2+4HmkKK1hTMugq2HQA=
        AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
        Endpoint = sg476.nordvpn.com:51820
        PersistentKeepalive = 25
        """;

    [Fact]
    public void BuildSplitTunnelConfig_AddsTableOffInsideInterfaceSection()
    {
        var result = MacSplitTunnelConfigService.BuildSplitTunnelConfig(NordConfig);

        var lines = result.Split('\n').Select(line => line.Trim()).ToList();
        var interfaceIndex = lines.IndexOf("[Interface]");
        interfaceIndex.Should().BeGreaterThanOrEqualTo(0);
        lines[interfaceIndex + 1].Should().Be("Table = off");
    }

    [Fact]
    public void BuildSplitTunnelConfig_RemovesDnsOverride()
    {
        var result = MacSplitTunnelConfigService.BuildSplitTunnelConfig(NordConfig);

        result.Should().NotContain("DNS");
        result.Should().NotContain("103.86.96.100");
    }

    [Fact]
    public void BuildSplitTunnelConfig_KeepsKeysAddressAndPeerSection()
    {
        var result = MacSplitTunnelConfigService.BuildSplitTunnelConfig(NordConfig);

        result.Should().Contain("PrivateKey = SECRETKEY=");
        result.Should().Contain("Address = 10.5.0.2/32");
        result.Should().Contain("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1");
        result.Should().Contain("Endpoint = sg476.nordvpn.com:51820");
    }

    [Fact]
    public void BuildSplitTunnelConfig_ReplacesExistingTableSetting()
    {
        const string configWithTable = """
            [Interface]
            PrivateKey = SECRETKEY=
            Table = auto

            [Peer]
            PublicKey = U3dKnkOJY5P9p6kEbEDGR7+K2+4HmkKK1hTMugq2HQA=
            AllowedIPs = 0.0.0.0/0
            Endpoint = sg476.nordvpn.com:51820
            """;

        var result = MacSplitTunnelConfigService.BuildSplitTunnelConfig(configWithTable);

        result.Should().Contain("Table = off");
        result.Should().NotContain("Table = auto");
    }

    [Fact]
    public void WriteSplitTunnelConfig_WritesDerivedFileNamedWgstSplit()
    {
        var workDir = Path.Combine(Path.GetTempPath(), $"wgst-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDir);
        try
        {
            var source = Path.Combine(workDir, "SG.conf");
            File.WriteAllText(source, NordConfig);

            var derivedPath = MacSplitTunnelConfigService.WriteSplitTunnelConfig(source, workDir);

            derivedPath.Should().Be(Path.Combine(workDir, "wgst-split.conf"));
            var written = File.ReadAllText(derivedPath);
            written.Should().Contain("Table = off");
            written.Should().NotContain("DNS");
            if (!OperatingSystem.IsWindows())
            {
                File.GetUnixFileMode(derivedPath)
                    .Should().Be(UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        finally
        {
            Directory.Delete(workDir, recursive: true);
        }
    }

    [Fact]
    public void ExtractDnsServers_ReadsCommaSeparatedInterfaceDns()
    {
        MacSplitTunnelConfigService.ExtractDnsServers(NordConfig)
            .Should().Equal("103.86.96.100", "103.86.99.100");
    }

    [Fact]
    public void ExtractDnsServers_MultipleDnsLines_CollectsAll()
    {
        const string config = """
            [Interface]
            dns = 10.0.0.1
            DNS = 10.0.0.2

            [Peer]
            AllowedIPs = 0.0.0.0/0
            """;

        MacSplitTunnelConfigService.ExtractDnsServers(config)
            .Should().Equal("10.0.0.1", "10.0.0.2");
    }

    [Fact]
    public void ExtractDnsServers_NoDns_ReturnsEmpty()
    {
        const string config = """
            [Interface]
            Address = 10.5.0.2/32

            [Peer]
            AllowedIPs = 0.0.0.0/0
            """;

        MacSplitTunnelConfigService.ExtractDnsServers(config).Should().BeEmpty();
    }

    [Fact]
    public void ExtractDnsServers_IgnoresDnsOutsideInterfaceSection()
    {
        const string config = """
            [Peer]
            DNS = 9.9.9.9
            AllowedIPs = 0.0.0.0/0
            """;

        MacSplitTunnelConfigService.ExtractDnsServers(config).Should().BeEmpty();
    }
}
