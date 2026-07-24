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

    [Fact]
    public void MergeIncremental_MergesTouchedDomainAndPreservesUnrelatedMetadata()
    {
        var state = new AppState(
            [new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>>
            {
                ["*.openai.com"] = ["203.0.113.10"],
                ["unrelated.example.com"] = ["198.51.100.40"]
            },
            [],
            LastKnownResolvedIpDetails: new Dictionary<string, List<ResolvedIpDetail>>
            {
                ["*.openai.com"] =
                [
                    new ResolvedIpDetail("203.0.113.10", "*.openai.com", ResolvedIpSourceKind.Direct)
                ],
                ["unrelated.example.com"] =
                [
                    new ResolvedIpDetail("198.51.100.40", "unrelated.example.com", ResolvedIpSourceKind.Direct)
                ]
            });
        var resolved = new[]
        {
            new ResolvedRule(
                new DomainRule("*.openai.com"),
                ["203.0.113.10", "203.0.113.11"],
                [
                    new ResolvedIpDetail("203.0.113.10", "auth.openai.com", ResolvedIpSourceKind.Learned),
                    new ResolvedIpDetail("203.0.113.11", "api.openai.com", ResolvedIpSourceKind.Learned)
                ])
        };

        var changed = ResolutionStateUpdater.MergeIncremental(state, resolved);

        changed.Should().BeTrue();
        state.LastKnownResolvedIps["*.openai.com"].Should().Equal("203.0.113.10", "203.0.113.11");
        state.LastKnownResolvedIpDetails["*.openai.com"].Should().Equal(
            new ResolvedIpDetail("203.0.113.10", "*.openai.com", ResolvedIpSourceKind.Direct),
            new ResolvedIpDetail("203.0.113.11", "api.openai.com", ResolvedIpSourceKind.Learned));
        state.LastKnownResolvedIps["unrelated.example.com"].Should().Equal("198.51.100.40");
        state.LastKnownResolvedIpDetails["unrelated.example.com"].Should().Equal(
            new ResolvedIpDetail("198.51.100.40", "unrelated.example.com", ResolvedIpSourceKind.Direct));
    }

    [Fact]
    public void MergeIncremental_WithSameValuesASecondTime_ReturnsFalse()
    {
        var state = new AppState(
            [new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>>(),
            []);
        var resolved = new[]
        {
            new ResolvedRule(
                new DomainRule("*.openai.com"),
                ["203.0.113.11"],
                [new ResolvedIpDetail("203.0.113.11", "api.openai.com", ResolvedIpSourceKind.Learned)])
        };

        ResolutionStateUpdater.MergeIncremental(state, resolved).Should().BeTrue();

        ResolutionStateUpdater.MergeIncremental(state, resolved).Should().BeFalse();
    }

    [Fact]
    public void MergeIncremental_RejectsStaleDisabledBypassExactAndDeletedRules()
    {
        var state = new AppState(
            [
                new DomainRule("*.disabled.example.com", false, DomainRouteMode.UseWireGuard),
                new DomainRule("*.bypass.example.com", true, DomainRouteMode.BypassWireGuard),
                new DomainRule("exact.example.com", true, DomainRouteMode.UseWireGuard)
            ],
            new Dictionary<string, List<string>>
            {
                ["unrelated.example.com"] = ["198.51.100.40"]
            },
            [],
            LastKnownResolvedIpDetails: new Dictionary<string, List<ResolvedIpDetail>>
            {
                ["unrelated.example.com"] =
                [
                    new ResolvedIpDetail("198.51.100.40", "unrelated.example.com", ResolvedIpSourceKind.Direct)
                ]
            });
        var resolved = new[]
        {
            new ResolvedRule(new DomainRule("*.disabled.example.com"), ["203.0.113.20"]),
            new ResolvedRule(new DomainRule("*.bypass.example.com"), ["203.0.113.21"]),
            new ResolvedRule(new DomainRule("exact.example.com"), ["203.0.113.22"]),
            new ResolvedRule(new DomainRule("*.deleted.example.com"), ["203.0.113.23"])
        };

        var changed = ResolutionStateUpdater.MergeIncremental(state, resolved);

        changed.Should().BeFalse();
        state.LastKnownResolvedIps.Should().ContainSingle("unrelated.example.com", ["198.51.100.40"]);
        state.LastKnownResolvedIpDetails.Keys.Should().ContainSingle()
            .Which.Should().Be("unrelated.example.com");
        state.LastKnownResolvedIpDetails["unrelated.example.com"].Should().Equal(
            new ResolvedIpDetail("198.51.100.40", "unrelated.example.com", ResolvedIpSourceKind.Direct));
    }

    [Fact]
    public void MergeIncremental_IgnoresDetailsOutsideResolvedIps()
    {
        var state = new AppState(
            [new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>>(),
            []);
        var resolved = new[]
        {
            new ResolvedRule(
                new DomainRule("*.openai.com"),
                ["203.0.113.10"],
                [
                    new ResolvedIpDetail("203.0.113.10", "auth.openai.com", ResolvedIpSourceKind.Learned),
                    new ResolvedIpDetail("203.0.113.11", "orphan.openai.com", ResolvedIpSourceKind.Learned)
                ])
        };

        ResolutionStateUpdater.MergeIncremental(state, resolved).Should().BeTrue();

        state.LastKnownResolvedIps["*.openai.com"].Should().Equal("203.0.113.10");
        state.LastKnownResolvedIpDetails["*.openai.com"].Should().Equal(
            new ResolvedIpDetail("203.0.113.10", "auth.openai.com", ResolvedIpSourceKind.Learned));
    }

    [Fact]
    public void MergeIncremental_CanonicalizesMixedCaseExistingKeysWithoutDuplicates()
    {
        var state = new AppState(
            [new DomainRule("*.OpenAI.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>>
            {
                ["*.OPENAI.COM"] = ["203.0.113.10"],
                ["unrelated.example.com"] = ["198.51.100.40"]
            },
            [],
            LastKnownResolvedIpDetails: new Dictionary<string, List<ResolvedIpDetail>>
            {
                ["*.OPENAI.COM"] =
                [
                    new ResolvedIpDetail("203.0.113.10", "*.OpenAI.com", ResolvedIpSourceKind.Direct)
                ],
                ["unrelated.example.com"] =
                [
                    new ResolvedIpDetail("198.51.100.40", "unrelated.example.com", ResolvedIpSourceKind.Direct)
                ]
            });
        var resolved = new[]
        {
            new ResolvedRule(
                new DomainRule("*.openai.com"),
                ["203.0.113.11"],
                [new ResolvedIpDetail("203.0.113.11", "api.openai.com", ResolvedIpSourceKind.Learned)])
        };

        ResolutionStateUpdater.MergeIncremental(state, resolved).Should().BeTrue();

        state.LastKnownResolvedIps.Keys.Should().BeEquivalentTo("*.OpenAI.com", "unrelated.example.com");
        state.LastKnownResolvedIpDetails.Keys.Should().BeEquivalentTo("*.OpenAI.com", "unrelated.example.com");
        state.LastKnownResolvedIps["*.OpenAI.com"].Should().Equal("203.0.113.10", "203.0.113.11");
        state.LastKnownResolvedIpDetails["*.OpenAI.com"].Should().Equal(
            new ResolvedIpDetail("203.0.113.10", "*.OpenAI.com", ResolvedIpSourceKind.Direct),
            new ResolvedIpDetail("203.0.113.11", "api.openai.com", ResolvedIpSourceKind.Learned));
        state.LastKnownResolvedIps["unrelated.example.com"].Should().Equal("198.51.100.40");
    }

    [Fact]
    public void MergeIncremental_RemovesExistingDetailsMissingFromExistingIps()
    {
        var state = new AppState(
            [new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>>
            {
                ["*.openai.com"] = ["203.0.113.10"]
            },
            [],
            LastKnownResolvedIpDetails: new Dictionary<string, List<ResolvedIpDetail>>
            {
                ["*.openai.com"] =
                [
                    new ResolvedIpDetail("203.0.113.10", "*.openai.com", ResolvedIpSourceKind.Direct),
                    new ResolvedIpDetail("203.0.113.99", "orphan.openai.com", ResolvedIpSourceKind.Learned)
                ]
            });
        var resolved = new[]
        {
            new ResolvedRule(
                new DomainRule("*.openai.com"),
                ["203.0.113.11"],
                [new ResolvedIpDetail("203.0.113.11", "api.openai.com", ResolvedIpSourceKind.Learned)])
        };

        ResolutionStateUpdater.MergeIncremental(state, resolved).Should().BeTrue();

        state.LastKnownResolvedIps["*.openai.com"].Should().Equal("203.0.113.10", "203.0.113.11");
        state.LastKnownResolvedIpDetails["*.openai.com"].Should().Equal(
            new ResolvedIpDetail("203.0.113.10", "*.openai.com", ResolvedIpSourceKind.Direct),
            new ResolvedIpDetail("203.0.113.11", "api.openai.com", ResolvedIpSourceKind.Learned));
    }
}
