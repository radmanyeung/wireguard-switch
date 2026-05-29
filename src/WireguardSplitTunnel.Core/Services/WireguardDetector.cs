using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

public interface IWireguardDetector
{
    bool TryGetActiveInterface(out string interfaceName);
}

public sealed class SystemWireguardDetector : IWireguardDetector
{
    public bool TryGetActiveInterface(out string interfaceName)
    {
        if (OperatingSystem.IsMacOS())
        {
            return TryGetMacInterface(out interfaceName);
        }

        return TryGetWindowsInterface(out interfaceName);
    }

    private static bool TryGetWindowsInterface(out string interfaceName)
    {
        var candidate = NetworkInterface
            .GetAllNetworkInterfaces()
            .FirstOrDefault(networkInterface =>
                networkInterface.OperationalStatus == OperationalStatus.Up
                && (networkInterface.Name.Contains("wireguard", StringComparison.OrdinalIgnoreCase)
                    || networkInterface.Description.Contains("wireguard", StringComparison.OrdinalIgnoreCase)));

        if (candidate is null)
        {
            interfaceName = string.Empty;
            return false;
        }

        interfaceName = candidate.Name;
        return true;
    }

    [SupportedOSPlatform("macos")]
    private static bool TryGetMacInterface(out string interfaceName)
    {
        // wg-quick records the WireGuard tunnel <-> utun mapping in /var/run/wireguard/<name>.name.
        // Each .name file's contents is the actual utun device (e.g. "utun5"), which is what
        // `route` and `ifconfig` need to address. We pick the first active mapping.
        const string wgRunDir = "/var/run/wireguard";
        if (Directory.Exists(wgRunDir))
        {
            foreach (var nameFile in Directory.EnumerateFiles(wgRunDir, "*.name"))
            {
                try
                {
                    var utun = File.ReadAllText(nameFile).Trim();
                    if (!string.IsNullOrWhiteSpace(utun) && IsInterfaceUp(utun))
                    {
                        interfaceName = utun;
                        return true;
                    }
                }
                catch
                {
                    // unreadable mapping — try next
                }
            }
        }

        // Fallback: pick the first up "utun" interface that has a peer-style point-to-point IPv4
        // address. This is best-effort — the .name file path above is authoritative for wg-quick.
        var fallback = NetworkInterface
            .GetAllNetworkInterfaces()
            .FirstOrDefault(nic =>
                nic.OperationalStatus == OperationalStatus.Up
                && nic.Name.StartsWith("utun", StringComparison.OrdinalIgnoreCase));

        if (fallback is not null)
        {
            interfaceName = fallback.Name;
            return true;
        }

        interfaceName = string.Empty;
        return false;
    }

    private static bool IsInterfaceUp(string name)
    {
        try
        {
            return NetworkInterface
                .GetAllNetworkInterfaces()
                .Any(nic =>
                    string.Equals(nic.Name, name, StringComparison.OrdinalIgnoreCase)
                    && nic.OperationalStatus == OperationalStatus.Up);
        }
        catch
        {
            return false;
        }
    }
}
