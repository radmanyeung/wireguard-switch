using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class LegacyOpenAiPresetMigrationServiceTests
{
    private static readonly string[] LegacyDomains =
    [
        "chatgpt.com",
        "*.chatgpt.com",
        "openai.com",
        "*.openai.com",
        "auth.openai.com",
        "api.openai.com",
        "platform.openai.com",
        "oaistatic.com",
        "*.oaistatic.com",
        "oaiusercontent.com",
        "*.oaiusercontent.com"
    ];

    private static readonly string[] HelperDomains =
    [
        "files.oaiusercontent.com",
        "challenges.cloudflare.com",
        "cdn.auth0.com"
    ];

    [Fact]
    public void Migrate_CompleteLegacyPresetWithUnrelatedRule_AddsAllHelperDomains()
    {
        var state = CreateCompleteLegacyState();
        state.DomainRules.Add(new DomainRule("example.com", false, DomainRouteMode.BypassWireGuard));

        var result = LegacyOpenAiPresetMigrationService.Migrate(state);

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

        var firstResult = LegacyOpenAiPresetMigrationService.Migrate(state);
        var secondResult = LegacyOpenAiPresetMigrationService.Migrate(state);

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
            string.Equals(rule.Domain, "platform.openai.com", StringComparison.OrdinalIgnoreCase));

        var result = LegacyOpenAiPresetMigrationService.Migrate(state);

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
            string.Equals(rule.Domain, "api.openai.com", StringComparison.OrdinalIgnoreCase));
        state.DomainRules[index] = state.DomainRules[index] with { Enabled = enabled, Mode = mode };

        var result = LegacyOpenAiPresetMigrationService.Migrate(state);

        result.Added.Should().Be(0);
        GetHelperRules(state).Should().BeEmpty();
    }

    [Fact]
    public void Migrate_DuplicateCustomizedLegacyRule_DoesNothing()
    {
        var state = CreateCompleteLegacyState();
        state.DomainRules.Add(new DomainRule(
            "AUTH.OPENAI.COM",
            false,
            DomainRouteMode.BypassWireGuard));

        var result = LegacyOpenAiPresetMigrationService.Migrate(state);

        result.Added.Should().Be(0);
        GetHelperRules(state).Should().BeEmpty();
    }

    [Fact]
    public void Migrate_CustomizedExistingHelper_PreservesItAndAddsOtherHelpers()
    {
        var state = CreateCompleteLegacyState();
        var customizedHelper = new DomainRule(
            "FILES.OAIUSERCONTENT.COM",
            false,
            DomainRouteMode.BypassWireGuard);
        state.DomainRules.Add(customizedHelper);

        var result = LegacyOpenAiPresetMigrationService.Migrate(state);

        result.Added.Should().Be(2);
        state.DomainRules.Should().ContainSingle(rule =>
            string.Equals(rule.Domain, "files.oaiusercontent.com", StringComparison.OrdinalIgnoreCase));
        state.DomainRules.Single(rule =>
            string.Equals(rule.Domain, "files.oaiusercontent.com", StringComparison.OrdinalIgnoreCase))
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
        rules[4] = rules[4] with { Domain = rules[4].Domain.ToUpperInvariant() };

        return new AppState(rules, new Dictionary<string, List<string>>(), []);
    }

    private static List<DomainRule> GetHelperRules(AppState state) => state.DomainRules
        .Where(rule => HelperDomains.Contains(rule.Domain, StringComparer.OrdinalIgnoreCase))
        .ToList();
}
