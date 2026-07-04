using System.Runtime.Versioning;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

public static class DefaultRouteInspector
{
    public static bool TryParseDefaultRouteInterface(string routeGetOutput, out string interfaceName)
    {
        foreach (var line in routeGetOutput.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("interface:", StringComparison.OrdinalIgnoreCase))
            {
                interfaceName = trimmed["interface:".Length..].Trim();
                return interfaceName.Length > 0;
            }
        }

        interfaceName = string.Empty;
        return false;
    }

    public static bool IsVpnInterface(string? interfaceName) =>
        !string.IsNullOrWhiteSpace(interfaceName)
        && interfaceName.Trim().StartsWith("utun", StringComparison.OrdinalIgnoreCase);

    /// <summary>Returns the IPv4 default-route interface, or null when it cannot be determined.</summary>
    [SupportedOSPlatform("macos")]
    public static Task<string?> GetDefaultRouteInterfaceAsync(CancellationToken cancellationToken) =>
        GetDefaultRouteInterfaceAsync(
            () => MacAdminShell.RunAsync("/sbin/route", "-n get default", cancellationToken));

    internal static async Task<string?> GetDefaultRouteInterfaceAsync(Func<Task<MacShellResult>> runRouteGet)
    {
        MacShellResult result;
        try
        {
            // `route -n get default` needs no root and prints an "interface:" line.
            result = await runRouteGet();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // "Cannot be determined" must surface as null, not as a crash in the start flow.
            return null;
        }

        if (result.ExitCode != 0)
        {
            return null;
        }

        return TryParseDefaultRouteInterface(result.StandardOutput, out var interfaceName)
            ? interfaceName
            : null;
    }
}
