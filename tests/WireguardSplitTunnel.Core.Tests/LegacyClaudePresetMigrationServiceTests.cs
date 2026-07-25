using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class LegacyClaudePresetMigrationServiceTests
{
    private static readonly string[] LegacyDomains =
    [
        "claude.ai",
        "*.claude.ai",
        "anthropic.com",
        "*.anthropic.com",
        "api.anthropic.com",
        "console.anthropic.com"
    ];

    private static readonly string[] HelperDomains =
    [
        "claude.com",
        "*.claude.com",
        "downloads.claude.ai"
    ];

    [Fact]
    public void Migrate_CompleteLegacyPresetWithUnrelatedRule_AddsAllHelperDomains()
    {
        var state = CreateCompleteLegacyState();
        state.DomainRules.Add(new DomainRule("example.com", false, DomainRouteMode.BypassWireGuard));

        var result = LegacyClaudePresetMigrationService.Migrate(state);

        result.Added.Should().Be(3);
        GetHelperRules(state).Select(rule => rule.Domain).Should().BeEquivalentTo(HelperDomains);
        GetHelperRules(state).Should().OnlyContain(rule =>
            rule.Enabled && rule.Mode == DomainRouteMode.UseWireGuard);
        state.DomainRules.Should().Contain(new DomainRule("example.com", false, DomainRouteMode.BypassWireGuard));
    }

    [Fact]
    public void Migrate_RunTwice_AddsNothingOnSecondRunAndCreatesNoDuplicates()
    {
        var state = CreateCompleteLegacyState();

        var firstResult = LegacyClaudePresetMigrationService.Migrate(state);
        var secondResult = LegacyClaudePresetMigrationService.Migrate(state);

        firstResult.Added.Should().Be(3);
        secondResult.Added.Should().Be(0);
        GetHelperRules(state).Should().HaveCount(3);
        GetHelperRules(state)
            .GroupBy(rule => rule.Domain, StringComparer.OrdinalIgnoreCase)
            .Should().OnlyContain(group => group.Count() == 1);
    }

    [Fact]
    public void Migrate_PartialLegacyPreset_DoesNothing()
    {
        var state = CreateCompleteLegacyState();
        state.DomainRules.RemoveAll(rule =>
            string.Equals(rule.Domain, "console.anthropic.com", StringComparison.OrdinalIgnoreCase));

        var result = LegacyClaudePresetMigrationService.Migrate(state);

        result.Added.Should().Be(0);
        GetHelperRules(state).Should().BeEmpty();
    }

    [Theory]
    [InlineData(false, DomainRouteMode.UseWireGuard)]
    [InlineData(true, DomainRouteMode.BypassWireGuard)]
    public void Migrate_LegacyRuleIsNotEnabledUseWireGuard_DoesNothing(
        bool enabled,
        DomainRouteMode mode)
    {
        var state = CreateCompleteLegacyState();
        var index = state.DomainRules.FindIndex(rule =>
            string.Equals(rule.Domain, "api.anthropic.com", StringComparison.OrdinalIgnoreCase));
        state.DomainRules[index] = state.DomainRules[index] with { Enabled = enabled, Mode = mode };

        var result = LegacyClaudePresetMigrationService.Migrate(state);

        result.Added.Should().Be(0);
        GetHelperRules(state).Should().BeEmpty();
    }

    [Fact]
    public void Migrate_DuplicateCustomizedLegacyRule_DoesNothing()
    {
        var state = CreateCompleteLegacyState();
        state.DomainRules.Add(new DomainRule(
            "CLAUDE.AI",
            false,
            DomainRouteMode.BypassWireGuard));

        var result = LegacyClaudePresetMigrationService.Migrate(state);

        result.Added.Should().Be(0);
        GetHelperRules(state).Should().BeEmpty();
    }

    [Fact]
    public void Migrate_DuplicateEligibleLegacyRule_StillAddsHelpers()
    {
        var state = CreateCompleteLegacyState();
        state.DomainRules.Add(new DomainRule(
            "CLAUDE.AI",
            true,
            DomainRouteMode.UseWireGuard));

        var result = LegacyClaudePresetMigrationService.Migrate(state);

        result.Added.Should().Be(3);
        GetHelperRules(state).Should().HaveCount(3);
    }

    [Fact]
    public void Migrate_CustomizedExistingHelper_PreservesItAndAddsOtherHelpers()
    {
        var state = CreateCompleteLegacyState();
        var customizedHelper = new DomainRule(
            "CLAUDE.COM",
            false,
            DomainRouteMode.BypassWireGuard);
        state.DomainRules.Add(customizedHelper);

        var result = LegacyClaudePresetMigrationService.Migrate(state);

        result.Added.Should().Be(2);
        state.DomainRules.Should().ContainSingle(rule =>
            string.Equals(rule.Domain, "claude.com", StringComparison.OrdinalIgnoreCase));
        state.DomainRules.Single(rule =>
            string.Equals(rule.Domain, "claude.com", StringComparison.OrdinalIgnoreCase))
            .Should().BeSameAs(customizedHelper);
        GetHelperRules(state)
            .Where(rule => !ReferenceEquals(rule, customizedHelper))
            .Should().OnlyContain(rule => rule.Enabled && rule.Mode == DomainRouteMode.UseWireGuard);
    }

    private static AppState CreateCompleteLegacyState()
    {
        var rules = LegacyDomains
            .Select(domain => new DomainRule(domain, true, DomainRouteMode.UseWireGuard))
            .ToList();
        rules[0] = rules[0] with { Domain = rules[0].Domain.ToUpperInvariant() };

        return new AppState(rules, new Dictionary<string, List<string>>(), []);
    }

    private static List<DomainRule> GetHelperRules(AppState state) => state.DomainRules
        .Where(rule => HelperDomains.Contains(rule.Domain, StringComparer.OrdinalIgnoreCase))
        .ToList();
}
