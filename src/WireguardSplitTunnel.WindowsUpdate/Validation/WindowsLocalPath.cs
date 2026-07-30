namespace WireguardSplitTunnel.WindowsUpdate.Validation;

internal static class WindowsLocalPath
{
    public static bool TryGetCanonicalLocalDosPath(string? path, out string? fullPath)
        => TryGetCanonicalLocalDosPath(path, root => new DriveInfo(root).DriveType, out fullPath);

    internal static bool TryGetCanonicalLocalDosPath(string? path, Func<string, DriveType> getDriveType, out string? fullPath)
    {
        fullPath = null;
        if (string.IsNullOrWhiteSpace(path)
            || path.StartsWith("\\\\", StringComparison.Ordinal)
            || path.StartsWith("//", StringComparison.Ordinal)
            || path.StartsWith("\\", StringComparison.Ordinal)
            || path.Length < 3
            || !char.IsAsciiLetter(path[0])
            || path[1] != ':'
            || path[2] != '\\')
        {
            return false;
        }

        try
        {
            var canonical = Path.GetFullPath(path);
            var root = Path.GetPathRoot(canonical);
            if (canonical.Length < 3
                || !char.IsAsciiLetter(canonical[0])
                || canonical[1] != ':'
                || canonical[2] != '\\'
                || !canonical.Equals(path, StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrEmpty(root))
            {
                return false;
            }

            try
            {
                if (getDriveType(root) != DriveType.Fixed)
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }

            fullPath = canonical;
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or IOException)
        {
            return false;
        }
    }
}
