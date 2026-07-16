using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacTunnelLifecyclePlannerTests
{
    [Theory]
    [InlineData(MacTunnelMappingPresence.Present)]
    [InlineData(MacTunnelMappingPresence.Unknown)]
    public void ShouldPreserveUnresolvedRawTunnel_PossiblyPresent_ReturnsTrue(
        MacTunnelMappingPresence presence)
    {
        MacTunnelLifecyclePlanner.ShouldPreserveUnresolvedRawTunnel(presence)
            .Should().BeTrue();
    }

    [Fact]
    public void ShouldPreserveUnresolvedRawTunnel_ConfirmedAbsent_ReturnsFalse()
    {
        MacTunnelLifecyclePlanner.ShouldPreserveUnresolvedRawTunnel(
                MacTunnelMappingPresence.Absent)
            .Should().BeFalse();
    }

    [Theory]
    [InlineData(MacTunnelMappingPresence.Present)]
    [InlineData(MacTunnelMappingPresence.Unknown)]
    public void ShouldAttemptCleanup_PossiblyPresent_ReturnsTrue(
        MacTunnelMappingPresence presence)
    {
        MacTunnelLifecyclePlanner.ShouldAttemptCleanup(presence)
            .Should().BeTrue();
    }

    [Fact]
    public void ShouldAttemptCleanup_ConfirmedAbsent_ReturnsFalse()
    {
        MacTunnelLifecyclePlanner.ShouldAttemptCleanup(MacTunnelMappingPresence.Absent)
            .Should().BeFalse();
    }
}
