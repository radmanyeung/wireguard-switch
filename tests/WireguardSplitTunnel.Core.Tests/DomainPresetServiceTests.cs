using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class DomainPresetServiceTests
{
    [Fact]
    public void ApplyPreset_AddsAiServicesDomainsAndSkipsExistingRules()
    {
        var state = new AppState(
            [new DomainRule("*.openai.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>>(),
            []);

        var result = DomainPresetService.ApplyPreset(state, DomainPreset.AiServicesBundle);

        result.Added.Should().BeGreaterThan(0);
        result.SkippedExisting.Should().Contain("*.openai.com");
        state.DomainRules.Select(rule => rule.Domain).Should().Contain(new[]
        {
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
            "*.oaiusercontent.com",
            "files.oaiusercontent.com",
            "challenges.cloudflare.com",
            "cdn.auth0.com",
            "claude.ai",
            "*.claude.ai",
            "anthropic.com",
            "*.anthropic.com",
            "api.anthropic.com",
            "console.anthropic.com",
            "gemini.google.com",
            "aistudio.google.com",
            "ai.google.dev",
            "notebooklm.google.com",
            "generativelanguage.googleapis.com",
            "accounts.google.com"
        });
        state.DomainRules.Should().OnlyContain(rule => rule.Enabled && rule.Mode == DomainRouteMode.UseWireGuard);
        state.DomainRules.Select(rule => rule.Domain).Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void GetPresetDomains_DoesNotIncludeOverBroadGoogleWildcards()
    {
        var domains = DomainPresetService.GetDomains(DomainPreset.GoogleAiGemini);

        domains.Should().NotContain(new[]
        {
            "*.google.com",
            "*.googleapis.com",
            "*.gstatic.com",
            "*.googleusercontent.com"
        });
    }
}
