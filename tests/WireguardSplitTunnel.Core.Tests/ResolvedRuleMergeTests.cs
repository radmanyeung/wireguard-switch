using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ResolvedRuleMergeTests
{
    [Fact]
    public void Merge_CombinesDirectAndLearnedIpsWithSourceDetails()
    {
        var rule = new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard);
        var direct = new[]
        {
            new ResolvedRule(rule, ["203.0.113.10"])
        };
        var learned = new[]
        {
            new ResolvedRule(rule, ["203.0.113.10", "203.0.113.11"],
            [
                new ResolvedIpDetail("203.0.113.10", "auth.openai.com", ResolvedIpSourceKind.Learned),
                new ResolvedIpDetail("203.0.113.11", "api.openai.com", ResolvedIpSourceKind.Learned)
            ])
        };

        var merged = ResolvedRuleMergeService.Merge(direct, learned);

        merged.Should().ContainSingle();
        var result = merged.Single();
        result.ResolvedIps.Should().Equal("203.0.113.10", "203.0.113.11");
        result.IpDetails.Should().Equal(
            new ResolvedIpDetail("203.0.113.10", "*.openai.com", ResolvedIpSourceKind.Direct),
            new ResolvedIpDetail("203.0.113.11", "api.openai.com", ResolvedIpSourceKind.Learned));
    }

    [Fact]
    public void ResolutionStateUpdater_StoresResolvedIpDetails()
    {
        var state = new AppState(
            [new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>>(),
            []);
        var resolved = new[]
        {
            new ResolvedRule(
                new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard),
                ["203.0.113.11"],
                [new ResolvedIpDetail("203.0.113.11", "api.openai.com", ResolvedIpSourceKind.Learned)])
        };

        ResolutionStateUpdater.Apply(state, resolved);

        state.LastKnownResolvedIps["*.openai.com"].Should().Equal("203.0.113.11");
        state.LastKnownResolvedIpDetails["*.openai.com"].Should().Equal(
            new ResolvedIpDetail("203.0.113.11", "api.openai.com", ResolvedIpSourceKind.Learned));
        ResolutionStateQueries.GetResolvedIpDetails(state, "*.openai.com").Should().ContainSingle();
    }
}
