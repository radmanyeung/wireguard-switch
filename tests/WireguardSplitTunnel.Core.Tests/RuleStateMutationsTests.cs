using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class RuleStateMutationsTests
{
    [Fact]
    public void TryAddDomainRule_AddsValidUniqueRule()
    {
        var state = new AppState([], new Dictionary<string, List<string>>(), []);

        var firstAdded = RuleStateMutations.TryAddDomainRule(state, "example.com", DomainRouteMode.UseWireGuard);
        var secondAdded = RuleStateMutations.TryAddDomainRule(state, "EXAMPLE.com", DomainRouteMode.BypassWireGuard);

        firstAdded.Should().BeTrue();
        secondAdded.Should().BeFalse();
        state.DomainRules.Should().ContainSingle(rule =>
            rule.Domain == "example.com"
            && rule.Enabled
            && rule.Mode == DomainRouteMode.UseWireGuard);
    }

    [Fact]
    public void TrySetRuleEnabled_UpdatesExistingRule()
    {
        var state = new AppState([new DomainRule("example.com", true)], new Dictionary<string, List<string>>(), []);

        var changed = RuleStateMutations.TrySetRuleEnabled(state, "example.com", false);

        changed.Should().BeTrue();
        state.DomainRules.Single().Enabled.Should().BeFalse();
    }

    [Fact]
    public void TrySetRuleMode_UpdatesExistingRule()
    {
        var state = new AppState([new DomainRule("example.com", true, DomainRouteMode.UseWireGuard)], new Dictionary<string, List<string>>(), []);

        var changed = RuleStateMutations.TrySetRuleMode(state, "example.com", DomainRouteMode.BypassWireGuard);

        changed.Should().BeTrue();
        state.DomainRules.Single().Mode.Should().Be(DomainRouteMode.BypassWireGuard);
    }

    [Fact]
    public void RemoveRule_RemovesExistingRule()
    {
        var state = new AppState([new DomainRule("one.com"), new DomainRule("two.com")], new Dictionary<string, List<string>>(), []);

        var removed = RuleStateMutations.RemoveRule(state, "one.com");

        removed.Should().BeTrue();
        state.DomainRules.Select(rule => rule.Domain).Should().Equal("two.com");
    }

    [Fact]
    public void Clone_CreatesIndependentCopy()
    {
        var state = new AppState(
            [new DomainRule("example.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>> { ["example.com"] = ["203.0.113.1"] },
            [new ManagedRouteEntry("example.com", "203.0.113.1")],
            "C:\\x.conf",
            true);

        var clone = RuleStateMutations.Clone(state);
        clone.DomainRules[0] = clone.DomainRules[0] with { Enabled = false, Mode = DomainRouteMode.BypassWireGuard };
        clone.LastKnownResolvedIps["example.com"].Add("203.0.113.2");
        clone.ManagedRouteSnapshot.Add(new ManagedRouteEntry("other.com", "203.0.113.9"));

        state.DomainRules[0].Enabled.Should().BeTrue();
        state.DomainRules[0].Mode.Should().Be(DomainRouteMode.UseWireGuard);
        state.LastKnownResolvedIps["example.com"].Should().Equal("203.0.113.1");
        state.ManagedRouteSnapshot.Should().ContainSingle();
    }
}
