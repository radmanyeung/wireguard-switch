using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class DefaultRouteInspectorTests
{
    // Real `route -n get default` output shapes on macOS.
    private const string VpnDefaultRouteOutput = """
           route to: default
        destination: default
               mask: default
          interface: utun4
              flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
        """;

    private const string NormalDefaultRouteOutput = """
           route to: default
        destination: default
               mask: default
            gateway: 192.168.1.1
          interface: en0
              flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
        """;

    [Fact]
    public void TryParseDefaultRouteInterface_ReadsInterfaceLine()
    {
        DefaultRouteInspector.TryParseDefaultRouteInterface(VpnDefaultRouteOutput, out var interfaceName)
            .Should().BeTrue();
        interfaceName.Should().Be("utun4");
    }

    [Fact]
    public void TryParseDefaultRouteInterface_ReadsPhysicalInterface()
    {
        DefaultRouteInspector.TryParseDefaultRouteInterface(NormalDefaultRouteOutput, out var interfaceName)
            .Should().BeTrue();
        interfaceName.Should().Be("en0");
    }

    [Fact]
    public void TryParseDefaultRouteInterface_FailsWhenNoInterfaceLine()
    {
        DefaultRouteInspector.TryParseDefaultRouteInterface("route: writing to routing socket", out var interfaceName)
            .Should().BeFalse();
        interfaceName.Should().BeEmpty();
    }

    [Theory]
    [InlineData("utun4", true)]
    [InlineData(" utun12 ", true)]
    [InlineData("en0", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsVpnInterface_MatchesUtunOnly(string? interfaceName, bool expected)
    {
        DefaultRouteInspector.IsVpnInterface(interfaceName).Should().Be(expected);
    }
}
