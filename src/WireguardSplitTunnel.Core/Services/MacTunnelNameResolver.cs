using System.Net.NetworkInformation;
using System.Runtime.Versioning;

namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Maps a wg-quick tunnel name (e.g. "wgst-split") to its live utun device by
/// reading /var/run/wireguard/&lt;name&gt;.name. Lets the app re-adopt a tunnel
/// left running by a previous session instead of forgetting it on restart.
/// </summary>
public static class MacTunnelNameResolver
{
    private const string WireguardRunDirectory = "/var/run/wireguard";

    public static string? ParseUtunName(string nameFileContent)
    {
        var candidate = nameFileContent.Trim();
        if (candidate.Length <= 4
            || !candidate.StartsWith("utun", StringComparison.OrdinalIgnoreCase)
            || !candidate[4..].All(char.IsDigit))
        {
            return null;
        }

        return candidate;
    }

    [SupportedOSPlatform("macos")]
    public static string? TryGetInterfaceForTunnel(string tunnelName) =>
        ResolveInterfaceForTunnel(
            tunnelName,
            allowSocketFallback: true,
            File.Exists,
            File.ReadAllText,
            () => Directory.EnumerateFiles(WireguardRunDirectory, "*.sock"),
            IsInterfaceUp);

    [SupportedOSPlatform("macos")]
    public static string? TryGetExactInterfaceForTunnel(string tunnelName) =>
        TryGetExactInterfaceForTunnel(
            tunnelName,
            File.Exists,
            File.ReadAllText,
            () => Directory.EnumerateFiles(WireguardRunDirectory, "*.sock"),
            IsInterfaceUp);

    internal static string? TryGetExactInterfaceForTunnel(
        string tunnelName,
        Func<string, bool> nameFileExists,
        Func<string, string> readNameFile,
        Func<IEnumerable<string>> enumerateSocketFiles,
        Func<string, bool> isInterfaceUp) =>
        ResolveInterfaceForTunnel(
            tunnelName,
            allowSocketFallback: false,
            nameFileExists,
            readNameFile,
            enumerateSocketFiles,
            isInterfaceUp);

    private static string? ResolveInterfaceForTunnel(
        string tunnelName,
        bool allowSocketFallback,
        Func<string, bool> nameFileExists,
        Func<string, string> readNameFile,
        Func<IEnumerable<string>> enumerateSocketFiles,
        Func<string, bool> isInterfaceUp)
    {
        var nameFile = Path.Combine(WireguardRunDirectory, tunnelName + ".name");
        try
        {
            if (!nameFileExists(nameFile))
            {
                return null;
            }

            string? utun;
            try
            {
                utun = ParseUtunName(readNameFile(nameFile));
            }
            catch (UnauthorizedAccessException) when (allowSocketFallback)
            {
                // wg-quick creates the .name file root-only. The tunnel exists
                // (the file is there); recover the utun from the socket file
                // names, which only require the directory to be listable.
                utun = ChooseUnambiguousSocketInterface(enumerateSocketFiles());
            }

            return utun is not null && isInterfaceUp(utun) ? utun : null;
        }
        catch
        {
            // Unreadable directory or racing teardown — treat as no tunnel.
            return null;
        }
    }

    internal static string? ChooseUnambiguousSocketInterface(IEnumerable<string> socketFiles)
    {
        var names = socketFiles
            .Select(Path.GetFileNameWithoutExtension)
            .OfType<string>()
            .Select(name => ParseUtunName(name))
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return names.Count == 1 ? names[0] : null;
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
