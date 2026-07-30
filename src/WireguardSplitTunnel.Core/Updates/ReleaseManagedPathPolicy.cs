namespace WireguardSplitTunnel.Core.Updates;

public static class ReleaseManagedPathPolicy
{
    private static readonly HashSet<string> ProtectedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "state.json", "applied-state.json", "temp-lists.json", "install.status.txt", "runtime.log"
    };

    public static bool IsProtectedPayloadPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }
        foreach (var segment in path.Split('/'))
        {
            if (segment.Equals("logs", StringComparison.OrdinalIgnoreCase)
                || segment.Equals("backup", StringComparison.OrdinalIgnoreCase)
                || segment.Equals("backups", StringComparison.OrdinalIgnoreCase)
                || segment.Equals("tmp", StringComparison.OrdinalIgnoreCase)
                || segment.Equals("temp", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        var name = path[(path.LastIndexOf('/') + 1)..];
        if (ProtectedNames.Contains(name)
            || name.Equals("update-metadata.json", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".conf", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".dpapi", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".bak", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".backup", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".temp", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return name.Contains("metadata", StringComparison.OrdinalIgnoreCase)
            && (name.Contains("candidate", StringComparison.OrdinalIgnoreCase)
                || name.Contains("staging", StringComparison.OrdinalIgnoreCase)
                || name.Contains("updater", StringComparison.OrdinalIgnoreCase)
                || name.Contains("local", StringComparison.OrdinalIgnoreCase)
                || name.Contains("protected", StringComparison.OrdinalIgnoreCase)
                || name.Contains("transaction", StringComparison.OrdinalIgnoreCase));
    }
}
