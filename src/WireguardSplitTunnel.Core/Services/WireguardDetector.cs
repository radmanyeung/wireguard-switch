using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using WireguardSplitTunnel.Core.Platform;

namespace WireguardSplitTunnel.Core.Services;

internal sealed record MacWireguardInterfaceCandidate(string Name, bool IsUp, bool HasIpv4);

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

            foreach (var socketFile in Directory.EnumerateFiles(wgRunDir, "*.sock"))
            {
                if (TryParseMacWireGuardSocketInterface(socketFile, out var utun) && IsInterfaceUp(utun))
                {
                    interfaceName = utun;
                    return true;
                }
            }
        }

        // Fallback: pick an up "utun" interface with IPv4 first. macOS often has
        // system utun0/utun1 interfaces that are IPv6-only and are not WireGuard.
        var fallback = ChoosePreferredMacFallbackInterface(
            NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.Name.StartsWith("utun", StringComparison.OrdinalIgnoreCase))
                .Select(ToMacCandidate));

        if (!string.IsNullOrWhiteSpace(fallback))
        {
            interfaceName = fallback;
            return true;
        }

        interfaceName = string.Empty;
        return false;
    }

    internal static string? ChoosePreferredMacFallbackInterface(IEnumerable<MacWireguardInterfaceCandidate> candidates)
    {
        // System utun interfaces (iCloud Private Relay etc.) are always up but
        // IPv6-only. A WireGuard tunnel from a .conf always has an IPv4 address,
        // so anything without IPv4 is not ours — exclude it, don't just rank it last.
        return candidates
            .Where(candidate => candidate.IsUp)
            .Where(candidate => candidate.HasIpv4)
            .Where(candidate => candidate.Name.StartsWith("utun", StringComparison.OrdinalIgnoreCase))
            .OrderBy(candidate => ParseUtunIndex(candidate.Name))
            .ThenBy(candidate => candidate.Name, StringComparer.OrdinalIgnoreCase)
            .Select(candidate => candidate.Name)
            .FirstOrDefault();
    }

    internal static bool TryParseMacWireGuardSocketInterface(string socketPath, out string interfaceName)
    {
        var fileName = Path.GetFileName(socketPath);
        if (!fileName.EndsWith(".sock", StringComparison.OrdinalIgnoreCase))
        {
            interfaceName = string.Empty;
            return false;
        }

        var candidate = fileName[..^".sock".Length];
        if (!candidate.StartsWith("utun", StringComparison.OrdinalIgnoreCase)
            || !candidate[4..].All(char.IsDigit))
        {
            interfaceName = string.Empty;
            return false;
        }

        interfaceName = candidate;
        return true;
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

    private static MacWireguardInterfaceCandidate ToMacCandidate(NetworkInterface nic)
    {
        var hasIpv4 = false;
        try
        {
            hasIpv4 = nic.GetIPProperties().UnicastAddresses.Any(address =>
                address.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
        }
        catch
        {
            hasIpv4 = false;
        }

        return new MacWireguardInterfaceCandidate(
            nic.Name,
            nic.OperationalStatus == OperationalStatus.Up,
            hasIpv4);
    }

    private static int ParseUtunIndex(string name)
    {
        if (name.Length <= 4 || !name.StartsWith("utun", StringComparison.OrdinalIgnoreCase))
        {
            return int.MaxValue;
        }

        return int.TryParse(name[4..], out var index) ? index : int.MaxValue;
    }
}
