using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public enum DomainPreset
{
    OpenAiChatGpt,
    ClaudeAnthropic,
    GoogleAiGemini,
    AiServicesBundle
}

public sealed record DomainPresetApplyResult(int Added, IReadOnlyCollection<string> SkippedExisting);

public static class DomainPresetService
{
    private static readonly string[] OpenAiChatGptDomains =
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

    private static readonly string[] ClaudeAnthropicDomains =
    [
        "claude.ai",
        "*.claude.ai",
        "anthropic.com",
        "*.anthropic.com",
        "api.anthropic.com",
        "console.anthropic.com"
    ];

    private static readonly string[] GoogleAiGeminiDomains =
    [
        "gemini.google.com",
        "aistudio.google.com",
        "ai.google.dev",
        "notebooklm.google.com",
        "generativelanguage.googleapis.com",
        "accounts.google.com"
    ];

    public static IReadOnlyCollection<string> GetDomains(DomainPreset preset) => preset switch
    {
        DomainPreset.OpenAiChatGpt => OpenAiChatGptDomains,
        DomainPreset.ClaudeAnthropic => ClaudeAnthropicDomains,
        DomainPreset.GoogleAiGemini => GoogleAiGeminiDomains,
        DomainPreset.AiServicesBundle => OpenAiChatGptDomains
            .Concat(ClaudeAnthropicDomains)
            .Concat(GoogleAiGeminiDomains)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray(),
        _ => []
    };

    public static DomainPresetApplyResult ApplyPreset(AppState state, DomainPreset preset)
    {
        var added = 0;
        var skipped = new List<string>();

        foreach (var domain in GetDomains(preset))
        {
            if (RuleStateMutations.TryAddDomainRule(state, domain, DomainRouteMode.UseWireGuard))
            {
                added++;
            }
            else if (state.DomainRules.Any(rule => string.Equals(rule.Domain, domain, StringComparison.OrdinalIgnoreCase)))
            {
                skipped.Add(domain);
            }
        }

        return new DomainPresetApplyResult(added, skipped);
    }
}
