using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WireguardDetectorTests
{
    [Theory]
    [InlineData("/var/run/wireguard/utun4.sock", "utun4")]
    [InlineData("/private/var/run/wireguard/utun12.sock", "utun12")]
    public void TryParseMacWireGuardSocketInterface_ParsesUtunSocketName(string path, string expected)
    {
        SystemWireguardDetector.TryParseMacWireGuardSocketInterface(path, out var interfaceName)
            .Should().BeTrue();
        interfaceName.Should().Be(expected);
    }

    [Theory]
    [InlineData("/var/run/wireguard/HK.name")]
    [InlineData("/var/run/wireguard/wg0.sock")]
    [InlineData("/var/run/wireguard/utun4")]
    public void TryParseMacWireGuardSocketInterface_IgnoresNonUtunSocketNames(string path)
    {
        SystemWireguardDetector.TryParseMacWireGuardSocketInterface(path, out var interfaceName)
            .Should().BeFalse();
        interfaceName.Should().BeEmpty();
    }
}
