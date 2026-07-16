using System.Runtime.Versioning;

namespace WireguardSplitTunnel.Core.Services;

public static class MacManagedTunnelInterfaceResolver
{
    [SupportedOSPlatform("macos")]
    public static string? TryGetSplitTunnelInterface() =>
        MacTunnelNameResolver.TryGetInterfaceForTunnel(
            MacSplitTunnelConfigService.SplitTunnelName);

    [SupportedOSPlatform("macos")]
    public static string? TryGetManagedInterface(string? activeRawTunnelName) =>
        ResolveManagedInterface(
            activeRawTunnelName,
            MacTunnelNameResolver.TryGetInterfaceForTunnel);

    internal static string? ResolveManagedInterface(
        string? activeRawTunnelName,
        Func<string, string?> resolveByTunnelName)
    {
        ArgumentNullException.ThrowIfNull(resolveByTunnelName);

        var splitInterface = resolveByTunnelName(
            MacSplitTunnelConfigService.SplitTunnelName);
        if (!string.IsNullOrWhiteSpace(splitInterface))
        {
            return splitInterface;
        }

        if (string.IsNullOrWhiteSpace(activeRawTunnelName))
        {
            return null;
        }

        return resolveByTunnelName(activeRawTunnelName.Trim());
    }
}
