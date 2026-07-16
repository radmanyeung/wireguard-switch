namespace WireguardSplitTunnel.Core.Services;

public static class MacTunnelDisablePlanner
{
    public static IReadOnlyList<string> BuildTargets(
        string? splitConfigPath,
        string? activeRawTunnelName,
        string? selectedConfigPath)
    {
        var targets = new List<(string Target, string TunnelName)>();

        if (!string.IsNullOrWhiteSpace(splitConfigPath))
        {
            targets.Add((splitConfigPath, WireguardConfigCatalog.GetTunnelName(splitConfigPath)));
        }

        if (!string.IsNullOrWhiteSpace(activeRawTunnelName))
        {
            var rawTunnelName = activeRawTunnelName.Trim();
            targets.Add((rawTunnelName, rawTunnelName));
        }

        if (!string.IsNullOrWhiteSpace(selectedConfigPath))
        {
            targets.Add((selectedConfigPath, WireguardConfigCatalog.GetTunnelName(selectedConfigPath)));
        }

        return targets
            .DistinctBy(target => target.TunnelName, StringComparer.OrdinalIgnoreCase)
            .Select(target => target.Target)
            .ToList();
    }
}
