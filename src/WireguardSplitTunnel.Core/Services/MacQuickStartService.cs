namespace WireguardSplitTunnel.Core.Services;

public enum MacQuickStartStatus
{
    Success = 1,
    MissingConfig = 2,
    MissingDependency = 3,
    TunnelFailed = 4,
    RoutesFailed = 5,
    BlockedByOtherVpn = 6
}

public sealed record MacQuickStartConfigResult(
    MacQuickStartStatus Status,
    string? SelectedConfigPath,
    string Message);

public sealed record MacQuickStartPlanResult(
    MacQuickStartStatus Status,
    string? SelectedConfigPath,
    bool ShouldStartTunnel,
    string Message);

public static class MacQuickStartService
{
    public static MacQuickStartPlanResult PlanStart(
        string? defaultRouteInterfaceName,
        string? savedConfigPath,
        IEnumerable<string> discoveredConfigPaths)
    {
        if (DefaultRouteInspector.IsVpnInterface(defaultRouteInterfaceName))
        {
            var iface = defaultRouteInterfaceName!.Trim();
            return new MacQuickStartPlanResult(
                MacQuickStartStatus.BlockedByOtherVpn,
                null,
                ShouldStartTunnel: false,
                $"Another VPN currently routes all traffic ({iface}). Disconnect the WireGuard app (or other VPN) first, then click Start AI VPN again.");
        }

        var selection = SelectConfig(savedConfigPath, discoveredConfigPaths);
        return new MacQuickStartPlanResult(
            selection.Status,
            selection.SelectedConfigPath,
            ShouldStartTunnel: selection.Status == MacQuickStartStatus.Success,
            selection.Message);
    }

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
