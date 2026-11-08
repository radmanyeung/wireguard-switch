namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Discovers WireGuard tunnel services installed on this Windows machine
/// (services named "WireGuardTunnel$&lt;name&gt;").
/// </summary>
public static class WindowsTunnelServiceDiscovery
{
    public const string ServiceNamePrefix = "WireGuardTunnel$";

    public static IReadOnlyList<WindowsTunnelServiceIdentity> ParseInstalledServiceIdentities(
        IEnumerable<string> serviceNames) =>
        serviceNames
            .Where(name => name.StartsWith(ServiceNamePrefix, StringComparison.OrdinalIgnoreCase))
            .Select(WindowsTunnelServiceIdentity.FromServiceName)
            .DistinctBy(identity => identity.TunnelName, StringComparer.OrdinalIgnoreCase)
            .OrderBy(identity => identity.TunnelName, StringComparer.OrdinalIgnoreCase)
            .ToList();

    public static IReadOnlyList<string> ParseInstalledTunnelNames(IEnumerable<string> serviceNames) =>
        ParseInstalledServiceIdentities(serviceNames.Where(name =>
                !name.StartsWith(ServiceNamePrefix, StringComparison.OrdinalIgnoreCase)
                || !string.IsNullOrWhiteSpace(name[ServiceNamePrefix.Length..])))
            .Select(identity => identity.TunnelName)
            .ToList();

    public static IReadOnlyList<string> ListInstalledTunnelNames() =>
        ParseInstalledTunnelNames(ListInstalledServiceNames(CancellationToken.None));

    internal static IReadOnlyList<WindowsTunnelServiceIdentity> ListInstalledServiceIdentities(
        CancellationToken cancellationToken) =>
        ParseInstalledServiceIdentities(ListInstalledServiceNames(cancellationToken));

    private static IReadOnlyList<string> ListInstalledServiceNames(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
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

        return servicesKey.GetSubKeyNames();
    }
}

public interface IWindowsTunnelServiceEnumerator
{
    Task<IReadOnlyList<WindowsTunnelServiceIdentity>> ListInstalledAsync(CancellationToken cancellationToken);
}

public sealed class RegistryWindowsTunnelServiceEnumerator : IWindowsTunnelServiceEnumerator
{
    public Task<IReadOnlyList<WindowsTunnelServiceIdentity>> ListInstalledAsync(
        CancellationToken cancellationToken) =>
        Task.FromResult(WindowsTunnelServiceDiscovery.ListInstalledServiceIdentities(cancellationToken));
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
