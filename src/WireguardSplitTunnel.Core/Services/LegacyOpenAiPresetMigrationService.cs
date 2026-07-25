using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public sealed record LegacyOpenAiPresetMigrationResult(int Added);

public static class LegacyOpenAiPresetMigrationService
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

    public static LegacyOpenAiPresetMigrationResult Migrate(AppState state)
    {
        var hasCompleteLegacyPreset = LegacyDomains.All(domain =>
        {
            var matchingRules = state.DomainRules
                .Where(rule => string.Equals(rule.Domain, domain, StringComparison.OrdinalIgnoreCase))
                .ToList();

            return matchingRules.Count > 0
                && matchingRules.All(rule =>
                    rule.Enabled && rule.Mode == DomainRouteMode.UseWireGuard);
        });

        if (!hasCompleteLegacyPreset)
        {
            return new LegacyOpenAiPresetMigrationResult(0);
        }

        var added = HelperDomains.Count(domain =>
            RuleStateMutations.TryAddDomainRule(state, domain, DomainRouteMode.UseWireGuard));

        return new LegacyOpenAiPresetMigrationResult(added);
    }
}
