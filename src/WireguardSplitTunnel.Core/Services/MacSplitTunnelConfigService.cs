namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Derives a split-tunnel variant of a WireGuard config: Table=off so wg-quick
/// adds no catch-all routes, and no DNS override so system DNS keeps working
/// when most traffic bypasses the tunnel. The app then routes only the AI
/// domain IPs through the tunnel interface.
/// </summary>
public static class MacSplitTunnelConfigService
{
    public const string SplitTunnelName = "wgst-split";

    public static string SplitTunnelConfigFileName => SplitTunnelName + ".conf";

    public static string BuildSplitTunnelConfig(string originalConfigText)
    {
        var lines = originalConfigText.Replace("\r\n", "\n").Split('\n');
        var output = new List<string>();
        var inInterfaceSection = false;

        foreach (var line in lines)
        {
            var trimmed = line.Trim();

            if (trimmed.StartsWith('['))
            {
                inInterfaceSection = trimmed.Equals("[Interface]", StringComparison.OrdinalIgnoreCase);
                output.Add(line);
                if (inInterfaceSection)
                {
                    output.Add("Table = off");
                }

                continue;
            }

            if (inInterfaceSection && (IsKey(trimmed, "DNS") || IsKey(trimmed, "Table")))
            {
                continue;
            }

            output.Add(line);
        }

        return string.Join('\n', output);

        static bool IsKey(string line, string key) =>
            line.StartsWith(key, StringComparison.OrdinalIgnoreCase)
            && line[key.Length..].TrimStart().StartsWith('=');
    }

    public static string WriteSplitTunnelConfig(string originalConfigPath, string dataDirectory)
    {
        string originalText;
        try
        {
            originalText = File.ReadAllText(originalConfigPath);
        }
        catch (UnauthorizedAccessException)
        {
            throw new InvalidOperationException(
                $"Cannot read the WireGuard config. Make it readable for this app: sudo chown $USER \"{originalConfigPath}\"");
        }

        Directory.CreateDirectory(dataDirectory);
        var derivedPath = Path.Combine(dataDirectory, SplitTunnelConfigFileName);
        var options = new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        using (var writer = new StreamWriter(new FileStream(derivedPath, options)))
        {
            writer.Write(BuildSplitTunnelConfig(originalText));
        }

        if (!OperatingSystem.IsWindows())
        {
            // UnixCreateMode only applies at creation; if the file already
            // existed with looser permissions from an earlier run, repair it.
            File.SetUnixFileMode(derivedPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return derivedPath;
    }
}
