using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacDnsRepairServiceTests
{
    [Fact]
    public void ParseNetworkServices_SkipsHeaderAndDisabledServices()
    {
        var output = """
            An asterisk (*) denotes that a network service is disabled.
            Thunderbolt Bridge
            Wi-Fi
            *Disabled VPN
            AT
            """;

        MacDnsRepairService.ParseNetworkServices(output)
            .Should().Equal("Thunderbolt Bridge", "Wi-Fi", "AT");
    }

    [Fact]
    public void ParseNetworkServices_EmptyOutput_ReturnsEmpty()
    {
        MacDnsRepairService.ParseNetworkServices(string.Empty).Should().BeEmpty();
    }

    [Fact]
    public void ParseDnsServers_IpPerLine_ReturnsIps()
    {
        MacDnsRepairService.ParseDnsServers("103.86.96.100\n103.86.99.100\n")
            .Should().Equal("103.86.96.100", "103.86.99.100");
    }

    [Fact]
    public void ParseDnsServers_NoneSetSentence_ReturnsEmpty()
    {
        MacDnsRepairService.ParseDnsServers("There aren't any DNS Servers set on Wi-Fi.")
            .Should().BeEmpty();
    }

    [Fact]
    public void PlanServicesToReset_ReturnsOnlyServicesUsingTunnelDns()
    {
        var current = new Dictionary<string, IReadOnlyList<string>>
        {
            ["Wi-Fi"] = ["103.86.96.100", "103.86.99.100"],
            ["Thunderbolt Bridge"] = [],
            ["AT"] = ["1.1.1.1"]
        };

        MacDnsRepairService.PlanServicesToReset(current, ["103.86.96.100", "103.86.99.100"])
            .Should().Equal("Wi-Fi");
    }

    [Fact]
    public void PlanServicesToReset_NoTunnelDns_ReturnsEmpty()
    {
        var current = new Dictionary<string, IReadOnlyList<string>>
        {
            ["Wi-Fi"] = ["103.86.96.100"]
        };

        MacDnsRepairService.PlanServicesToReset(current, []).Should().BeEmpty();
    }

    [Fact]
    public void BuildResetScript_EmitsOneNetworksetupLinePerService()
    {
        var script = MacDnsRepairService.BuildResetScript(["Wi-Fi", "My Service"]);

        script.Should().Contain("/usr/sbin/networksetup -setdnsservers \"Wi-Fi\" Empty");
        script.Should().Contain("/usr/sbin/networksetup -setdnsservers \"My Service\" Empty");
    }

    [Fact]
    public void BuildResetScript_NoServices_ReturnsEmpty()
    {
        MacDnsRepairService.BuildResetScript([]).Should().BeEmpty();
    }
}
