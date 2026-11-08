namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Builds a non-short-circuiting batch that attempts every exact tunnel target.
/// </summary>
public static class WindowsCloseDisconnectCommandBuilder
{
    public static string BuildArguments(
        string wireguardExePath,
        IEnumerable<WindowsTunnelServiceIdentity> targets)
    {
        const string failureVariable = "__WST_CLOSE_DISCONNECT_FAILED";
        var commands = targets
            .DistinctBy(target => target.TunnelName, StringComparer.OrdinalIgnoreCase)
            .OrderBy(target => target.TunnelName, StringComparer.OrdinalIgnoreCase)
            .Select(target =>
                $"{Quote(wireguardExePath)} {WireguardConfigCatalog.BuildUninstallTunnelArgs(target.TunnelName)}"
                + $" || set \"{failureVariable}=1\"")
            .ToArray();
        if (commands.Length == 0) return string.Empty;

        return $"set \"{failureVariable}=\" & {string.Join(" & ", commands)}"
            + $" & if defined {failureVariable} exit /b 1";
    }

    private static string Quote(string value) => $"\"{value}\"";
}
