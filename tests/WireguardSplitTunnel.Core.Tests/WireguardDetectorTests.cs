using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WireguardDetectorTests
{
    [Fact]
    public void ChoosePreferredMacFallbackInterface_PrefersIpv4UtunOverIpv6OnlyUtun()
    {
        var selected = SystemWireguardDetector.ChoosePreferredMacFallbackInterface(
            [
                new MacWireguardInterfaceCandidate("utun0", IsUp: true, HasIpv4: false),
                new MacWireguardInterfaceCandidate("utun1", IsUp: true, HasIpv4: false),
                new MacWireguardInterfaceCandidate("utun4", IsUp: true, HasIpv4: true)
            ]);

        selected.Should().Be("utun4");
    }

    [Fact]
    public void ChoosePreferredMacFallbackInterface_IgnoresDownInterfaces()
    {
        var selected = SystemWireguardDetector.ChoosePreferredMacFallbackInterface(
            [
                new MacWireguardInterfaceCandidate("utun2", IsUp: false, HasIpv4: true),
                new MacWireguardInterfaceCandidate("utun3", IsUp: true, HasIpv4: true)
            ]);

        selected.Should().Be("utun3");
    }

    [Fact]
    public void ChoosePreferredMacFallbackInterface_ReturnsNullWhenOnlyIpv6SystemUtunsExist()
    {
        // A Mac with no WireGuard running still has up, IPv6-only utun0-3
        // (iCloud Private Relay etc.). They must never be reported as tunnels.
        var selected = SystemWireguardDetector.ChoosePreferredMacFallbackInterface(
            [
                new MacWireguardInterfaceCandidate("utun0", IsUp: true, HasIpv4: false),
                new MacWireguardInterfaceCandidate("utun1", IsUp: true, HasIpv4: false),
                new MacWireguardInterfaceCandidate("utun2", IsUp: true, HasIpv4: false),
                new MacWireguardInterfaceCandidate("utun3", IsUp: true, HasIpv4: false)
            ]);

        selected.Should().BeNull();
    }

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
