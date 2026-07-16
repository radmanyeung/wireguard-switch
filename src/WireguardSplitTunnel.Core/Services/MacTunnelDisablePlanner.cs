namespace WireguardSplitTunnel.Core.Services;

public static class MacTunnelDisablePlanner
{
    public static IReadOnlyList<string> BuildTargets(
        string? splitConfigPath,
        string? activeRawTunnelName,
        string? selectedConfigPath)
    {
        var targets = new List<string>();

        if (!string.IsNullOrWhiteSpace(splitConfigPath))
        {
            targets.Add(splitConfigPath);
        }

        if (!string.IsNullOrWhiteSpace(activeRawTunnelName))
        {
            targets.Add(activeRawTunnelName.Trim());
        }

        if (!string.IsNullOrWhiteSpace(selectedConfigPath))
        {
            targets.Add(WireguardConfigCatalog.GetTunnelName(selectedConfigPath));
        }

        return targets
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
