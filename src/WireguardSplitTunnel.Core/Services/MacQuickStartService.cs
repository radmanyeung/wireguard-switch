namespace WireguardSplitTunnel.Core.Services;

public enum MacQuickStartStatus
{
    Success = 1,
    MissingConfig = 2,
    MissingDependency = 3,
    TunnelFailed = 4,
    RoutesFailed = 5
}

public sealed record MacQuickStartConfigResult(
    MacQuickStartStatus Status,
    string? SelectedConfigPath,
    string Message);

public static class MacQuickStartService
{
    public static MacQuickStartConfigResult SelectConfig(
        string? savedConfigPath,
        IEnumerable<string> discoveredConfigPaths)
    {
        var discovered = discoveredConfigPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => path.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(WireguardConfigCatalog.GetTunnelName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (!string.IsNullOrWhiteSpace(savedConfigPath))
        {
            var saved = discovered.FirstOrDefault(path =>
                string.Equals(path, savedConfigPath.Trim(), StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(saved))
            {
                return new MacQuickStartConfigResult(
                    MacQuickStartStatus.Success,
                    saved,
                    $"Using saved config: {Path.GetFileName(saved)}");
            }
        }

        if (discovered.Count == 1)
        {
            return new MacQuickStartConfigResult(
                MacQuickStartStatus.Success,
                discovered[0],
                $"Using config: {Path.GetFileName(discovered[0])}");
        }

        if (discovered.Count == 0)
        {
            return new MacQuickStartConfigResult(
                MacQuickStartStatus.MissingConfig,
                null,
                "No WireGuard configs found. Copy a .conf file to /opt/homebrew/etc/wireguard, then refresh configs.");
        }

        return new MacQuickStartConfigResult(
            MacQuickStartStatus.MissingConfig,
            null,
            "Choose a WireGuard config, then click Start AI VPN again.");
    }
}
