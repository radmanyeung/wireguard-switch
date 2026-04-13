using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ResolutionStateUpdaterTests
{
    [Fact]
    public void Apply_UpdatesResolvedIpsForEnabledRules()
    {
        var state = new AppState(
            [new DomainRule("one.example.com", true, DomainRouteMode.UseWireGuard), new DomainRule("two.example.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>>(),
            []);

        var resolved = new[]
        {
            new ResolvedRule(new DomainRule("one.example.com", true, DomainRouteMode.UseWireGuard), ["203.0.113.1", "203.0.113.2"]),
            new ResolvedRule(new DomainRule("two.example.com", true, DomainRouteMode.UseWireGuard), ["198.51.100.9"])
        };

        ResolutionStateUpdater.Apply(state, resolved);

        state.LastKnownResolvedIps["one.example.com"].Should().Equal("203.0.113.1", "203.0.113.2");
        state.LastKnownResolvedIps["two.example.com"].Should().Equal("198.51.100.9");
    }

    [Fact]
    public void Apply_RemovesMappingsForDisabledOrDeletedRules()
    {
        var state = new AppState(
            [
                new DomainRule("enabled.example.com", true, DomainRouteMode.UseWireGuard),
                new DomainRule("disabled.example.com", false, DomainRouteMode.UseWireGuard),
                new DomainRule("also-enabled.example.com", true, DomainRouteMode.BypassWireGuard)
            ],
            new Dictionary<string, List<string>>
            {
                ["enabled.example.com"] = ["203.0.113.10"],
                ["disabled.example.com"] = ["203.0.113.11"],
                ["also-enabled.example.com"] = ["203.0.113.12"],
                ["deleted.example.com"] = ["203.0.113.13"]
            },
            []);

        var resolved =
            new[]
            {
                new ResolvedRule(new DomainRule("enabled.example.com", true, DomainRouteMode.UseWireGuard), ["203.0.113.99"]),
                new ResolvedRule(new DomainRule("also-enabled.example.com", true, DomainRouteMode.BypassWireGuard), ["203.0.113.77"])
            };

        ResolutionStateUpdater.Apply(state, resolved);

        state.LastKnownResolvedIps.Keys.Should().BeEquivalentTo("enabled.example.com", "also-enabled.example.com");
        state.LastKnownResolvedIps["enabled.example.com"].Should().Equal("203.0.113.99");
        state.LastKnownResolvedIps["also-enabled.example.com"].Should().Equal("203.0.113.77");
    }
}
