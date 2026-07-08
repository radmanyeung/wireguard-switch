namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Rewrites raw macOS shell errors into actionable hints without ever hiding
/// the underlying message. Hints are additive: the raw text stays visible so
/// a mismatched heuristic can never mask the real failure.
/// </summary>
public static class MacErrorPresenter
{
    private static readonly string[] BashCandidates =
    [
        "/opt/homebrew/bin/bash",
        "/usr/local/bin/bash"
    ];

    public static string ToFriendly(string message) => ToFriendly(message, File.Exists);

    public static string ToFriendly(string message, Func<string, bool> fileExists)
    {
        var hint = FindHint(message, fileExists);
        return hint is null ? message : $"{hint}\nDetails: {message}";
    }

    private static string? FindHint(string message, Func<string, bool> fileExists)
    {
        var looksLikeMissingBash =
            message.Contains("/opt/homebrew/bin/bash: No such file or directory", StringComparison.OrdinalIgnoreCase)
            || message.Contains("bad interpreter", StringComparison.OrdinalIgnoreCase);
        if (looksLikeMissingBash && !BashCandidates.Any(fileExists))
        {
            return "Homebrew Bash is missing. Run: brew install bash";
        }

        if (message.Contains("wg-quick not found", StringComparison.OrdinalIgnoreCase))
        {
            return "WireGuard tools are missing. Run: brew install wireguard-tools bash";
        }

        if (message.Contains("Operation not permitted", StringComparison.OrdinalIgnoreCase)
            && message.Contains(".conf", StringComparison.OrdinalIgnoreCase))
        {
            return "macOS blocked that config path. Copy the .conf file to /opt/homebrew/etc/wireguard, refresh configs, and choose it there.";
        }

        return null;
    }
}
