using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class DomainRouteApplyPlannerTests
{
    [Fact]
    public void Build_ReaddsCurrentResolvedIpsAndRemovesStaleSnapshotIps()
    {
        var previousSnapshot = new[]
        {
            new ManagedRouteEntry("old.example.com", "203.0.113.10"),
            new ManagedRouteEntry("chatgpt.com", "104.18.32.47")
        };
        var resolved = new[]
        {
            new ResolvedRule(new DomainRule("chatgpt.com"), ["104.18.32.47", "172.64.155.209"]),
            new ResolvedRule(new DomainRule("api.openai.com"), ["172.64.155.209"])
        };

        var plan = DomainRouteApplyPlanner.Build(previousSnapshot, resolved);

        plan.Snapshot.Should().Equal(
            new ManagedRouteEntry("chatgpt.com", "104.18.32.47"),
            new ManagedRouteEntry("chatgpt.com", "172.64.155.209"));
        plan.ToAdd.Should().Equal("104.18.32.47", "172.64.155.209");
        plan.ToRemove.Should().Equal("203.0.113.10");
    }
}
