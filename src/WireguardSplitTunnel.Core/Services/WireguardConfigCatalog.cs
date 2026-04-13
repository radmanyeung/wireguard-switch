namespace WireguardSplitTunnel.Core.Services;

public static class WireguardConfigCatalog
{
    public static IReadOnlyList<string> DefaultConfigDirectories { get; } =
    [
        "C:\\Program Files\\WireGuard\\Data\\Configurations",
        "C:\\wireguard nord\\"
    ];

    public static string GetTunnelName(string configPath)
    {
        var fileName = Path.GetFileName(configPath);

        if (fileName.EndsWith(".conf.dpapi", StringComparison.OrdinalIgnoreCase))
        {
            return fileName[..^".conf.dpapi".Length];
        }

        if (fileName.EndsWith(".conf", StringComparison.OrdinalIgnoreCase))
        {
            return fileName[..^".conf".Length];
        }

        return fileName;
    }

    public static string BuildInstallTunnelArgs(string configPath) =>
        $"/installtunnelservice \"{configPath}\"";

    public static List<string> DiscoverConfigPaths(IEnumerable<string>? directories = null)
    {
        var output = new List<string>();
        var scanDirectories = directories?.ToList() ?? DefaultConfigDirectories.ToList();

        foreach (var directory in scanDirectories)
        {
            if (!Directory.Exists(directory))
            {
                continue;
            }

            output.AddRange(Directory.GetFiles(directory, "*.conf.dpapi"));
            output.AddRange(Directory.GetFiles(directory, "*.conf"));
        }

        return output
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
