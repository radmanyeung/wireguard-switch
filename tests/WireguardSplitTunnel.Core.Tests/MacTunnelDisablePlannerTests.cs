using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacTunnelDisablePlannerTests
{
    [Fact]
    public void BuildTargets_NamedInputs_DeduplicatesTunnelNames()
    {
        var result = MacTunnelDisablePlanner.BuildTargets(
            "/data/wgst-split.conf",
            "SG",
            "/opt/homebrew/etc/wireguard/SG.conf");

        result.Should().Equal("/data/wgst-split.conf", "SG");
        result.Should().NotContain("utun4");
    }

    [Fact]
    public void BuildTargets_NoNamedInputs_ReturnsEmptyInsteadOfUsingActiveInterface()
    {
        MacTunnelDisablePlanner.BuildTargets(null, null, null)
            .Should().BeEmpty();
    }

    [Fact]
    public void BuildTargets_SelectedConfig_UsesTunnelNameNotConfigPath()
    {
        MacTunnelDisablePlanner.BuildTargets(
                null,
                null,
                "/opt/homebrew/etc/wireguard/nordusa1.conf")
            .Should().Equal("nordusa1");
    }
}
