using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class IncrementalDomainRouteApplyPlannerTests
{
    [Fact]
    public void Build_AddsOnlyLateIpv4AddressAndRetainsEntireExistingSnapshot()
    {
        var state = new AppState(
            [new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>>(),
            [
                new ManagedRouteEntry("old.example.com", "203.0.113.10"),
                new ManagedRouteEntry("*.openai.com", "198.51.100.20")
            ]);
        var learned = new[]
        {
            new ResolvedRule(
                new DomainRule("*.openai.com"),
                ["198.51.100.20", "198.51.100.21", "2001:db8::21", "not-an-ip"])
        };

        var plan = IncrementalDomainRouteApplyPlanner.Build(state, learned);

        plan.Snapshot.Should().Equal(
            new ManagedRouteEntry("old.example.com", "203.0.113.10"),
            new ManagedRouteEntry("*.openai.com", "198.51.100.20"),
            new ManagedRouteEntry("*.openai.com", "198.51.100.21"));
        plan.ToAdd.Should().Equal("198.51.100.21");
        plan.LearnedRules.Should().ContainSingle()
            .Which.ResolvedIps.Should().Equal("198.51.100.20", "198.51.100.21");
    }

    [Fact]
    public void Build_AfterSnapshotUpdate_DoesNotAddTheSameAddressAgain()
    {
        var state = new AppState(
            [new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>>(),
            [new ManagedRouteEntry("*.openai.com", "198.51.100.21")]);
        var learned = new[]
        {
            new ResolvedRule(new DomainRule("*.openai.com"), ["198.51.100.21"])
        };

        var plan = IncrementalDomainRouteApplyPlanner.Build(state, learned);

        plan.Snapshot.Should().Equal(new ManagedRouteEntry("*.openai.com", "198.51.100.21"));
        plan.ToAdd.Should().BeEmpty();
    }

    [Fact]
    public void Build_RejectsDisabledBypassAndExactCurrentRules()
    {
        var state = new AppState(
            [
                new DomainRule("*.disabled.example.com", false, DomainRouteMode.UseWireGuard),
                new DomainRule("*.bypass.example.com", true, DomainRouteMode.BypassWireGuard),
                new DomainRule("exact.example.com", true, DomainRouteMode.UseWireGuard)
            ],
            new Dictionary<string, List<string>>(),
            [new ManagedRouteEntry("old.example.com", "203.0.113.10")]);
        var learned = new[]
        {
            new ResolvedRule(new DomainRule("*.disabled.example.com"), ["198.51.100.30"]),
            new ResolvedRule(new DomainRule("*.bypass.example.com"), ["198.51.100.31"]),
            new ResolvedRule(new DomainRule("exact.example.com"), ["198.51.100.32"])
        };

        var plan = IncrementalDomainRouteApplyPlanner.Build(state, learned);

        plan.Snapshot.Should().Equal(new ManagedRouteEntry("old.example.com", "203.0.113.10"));
        plan.ToAdd.Should().BeEmpty();
        plan.LearnedRules.Should().BeEmpty();
    }

    [Fact]
    public void Build_SortsAcceptedOutputAndPrefersDirectDuplicateDetail()
    {
        var state = new AppState(
            [new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>>(),
            []);
        var learned = new[]
        {
            new ResolvedRule(
                new DomainRule("*.openai.com"),
                ["198.51.100.12", "198.51.100.10", "198.51.100.11", "198.51.100.10"],
                [
                    new ResolvedIpDetail("198.51.100.11", "api.openai.com", ResolvedIpSourceKind.Learned),
                    new ResolvedIpDetail("198.51.100.10", "auth.openai.com", ResolvedIpSourceKind.Learned),
                    new ResolvedIpDetail("198.51.100.11", "*.openai.com", ResolvedIpSourceKind.Direct),
                    new ResolvedIpDetail("198.51.100.12", "cdn.openai.com", ResolvedIpSourceKind.Learned)
                ])
        };

        var plan = IncrementalDomainRouteApplyPlanner.Build(state, learned);

        plan.ToAdd.Should().Equal("198.51.100.10", "198.51.100.11", "198.51.100.12");
        plan.Snapshot.Should().Equal(
            new ManagedRouteEntry("*.openai.com", "198.51.100.10"),
            new ManagedRouteEntry("*.openai.com", "198.51.100.11"),
            new ManagedRouteEntry("*.openai.com", "198.51.100.12"));
        var accepted = plan.LearnedRules.Should().ContainSingle().Which;
        accepted.ResolvedIps.Should().Equal("198.51.100.10", "198.51.100.11", "198.51.100.12");
        accepted.IpDetails.Should().Equal(
            new ResolvedIpDetail("198.51.100.10", "auth.openai.com", ResolvedIpSourceKind.Learned),
            new ResolvedIpDetail("198.51.100.11", "*.openai.com", ResolvedIpSourceKind.Direct),
            new ResolvedIpDetail("198.51.100.12", "cdn.openai.com", ResolvedIpSourceKind.Learned));
    }
}
