namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Discovers WireGuard tunnel services installed on this Windows machine
/// (services named "WireGuardTunnel$&lt;name&gt;").
/// </summary>
public static class WindowsTunnelServiceDiscovery
{
    public const string ServiceNamePrefix = "WireGuardTunnel$";

    public static IReadOnlyList<string> ParseInstalledTunnelNames(IEnumerable<string> serviceNames) =>
        serviceNames
            .Where(name => name.StartsWith(ServiceNamePrefix, StringComparison.OrdinalIgnoreCase))
            .Select(name => name[ServiceNamePrefix.Length..])
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();

    public static IReadOnlyList<string> ListInstalledTunnelNames()
    {
        if (!OperatingSystem.IsWindows())
        {
            return [];
        }

        using var servicesKey = Microsoft.Win32.Registry.LocalMachine
            .OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (servicesKey is null)
        {
            return [];
        }

        return ParseInstalledTunnelNames(servicesKey.GetSubKeyNames());
    }
}

/// <summary>
/// Builds the elevated command line for "Enable Now": uninstall every
/// installed WireGuard tunnel service first (including the selected one, so
/// re-enabling is idempotent), then install the selected config. This makes
/// Enable Now deterministic — exactly the user's chosen tunnel runs.
/// </summary>
public static class WindowsEnableTunnelCommandBuilder
{
    public static string BuildArguments(
        string wireguardExePath,
        string selectedConfigPath,
        IEnumerable<string> installedTunnelNames)
    {
        var commands = new List<string>();

        foreach (var tunnelName in installedTunnelNames
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
        {
            commands.Add($"{Quote(wireguardExePath)} {WireguardConfigCatalog.BuildUninstallTunnelArgs(tunnelName)}");
        }

        commands.Add($"{Quote(wireguardExePath)} {WireguardConfigCatalog.BuildInstallTunnelArgs(selectedConfigPath)}");
        return string.Join(" & ", commands);
    }

    private static string Quote(string value) => $"\"{value}\"";
}
