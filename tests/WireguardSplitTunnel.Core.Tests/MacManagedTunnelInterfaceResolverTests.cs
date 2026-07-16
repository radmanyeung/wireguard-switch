using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacManagedTunnelInterfaceResolverTests
{
    [Fact]
    public void ResolveManagedInterface_SplitMappingWinsOverRawTunnel()
    {
        var calls = new List<string>();
        string? Resolve(string name)
        {
            calls.Add(name);
            return name switch
            {
                MacSplitTunnelConfigService.SplitTunnelName => "utun5",
                "SG" => "utun6",
                _ => null
            };
        }

        var result = MacManagedTunnelInterfaceResolver.ResolveManagedInterface("SG", Resolve);

        result.Should().Be("utun5");
        calls.Should().Equal(MacSplitTunnelConfigService.SplitTunnelName);
    }

    [Fact]
    public void ResolveManagedInterface_UnreadableSplitMappingAndSingleUnrelatedSocket_ReturnsNull()
    {
        const string tailscaleInterface = "utun4";

        var result = MacManagedTunnelInterfaceResolver.ResolveManagedInterface(
            activeRawTunnelName: null,
            resolveByTunnelName: name =>
                MacTunnelNameResolver.TryGetExactInterfaceForTunnel(
                    name,
                    nameFileExists: _ => true,
                    readNameFile: _ => throw new UnauthorizedAccessException(),
                    enumerateSocketFiles: () => ["/var/run/wireguard/utun4.sock"],
                    isInterfaceUp: candidate => candidate == tailscaleInterface));

        result.Should().BeNull();
        result.Should().NotBe(tailscaleInterface);
    }

    [Fact]
    public void ResolveManagedInterface_ExplicitRawTunnel_ResolvesExactName()
    {
        var requestedNames = new List<string>();
        string? Resolve(string name)
        {
            requestedNames.Add(name);
            return name == "SG" ? "utun6" : null;
        }

        var result = MacManagedTunnelInterfaceResolver.ResolveManagedInterface("  SG  ", Resolve);

        result.Should().Be("utun6");
        requestedNames.Should().Equal(MacSplitTunnelConfigService.SplitTunnelName, "SG");
    }

    [Fact]
    public void ResolveManagedInterface_NoNamedMappings_ReturnsNull()
    {
        MacManagedTunnelInterfaceResolver.ResolveManagedInterface("SG", _ => null)
            .Should().BeNull();
    }
}
