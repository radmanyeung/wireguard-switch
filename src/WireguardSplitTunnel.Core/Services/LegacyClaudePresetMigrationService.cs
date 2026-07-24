using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public sealed record LegacyClaudePresetMigrationResult(int Added);

public static class LegacyClaudePresetMigrationService
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

    public static LegacyClaudePresetMigrationResult Migrate(AppState state)
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
            return new LegacyClaudePresetMigrationResult(0);
        }

        var added = HelperDomains.Count(domain =>
            RuleStateMutations.TryAddDomainRule(state, domain, DomainRouteMode.UseWireGuard));

        return new LegacyClaudePresetMigrationResult(added);
    }
}
