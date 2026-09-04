namespace WireguardSplitTunnel.Core.Services;

/// <summary>
/// Decides where the application may append its runtime.log.
/// A launched installation under Program Files must stay byte-identical to
/// the release manifest, so log files are never written inside protected
/// install roots; the per-user data directory is always kept.
/// </summary>
public static class RuntimeLogCandidatePolicy
{
    public static IReadOnlyList<string> ExcludeProtectedRoots(
        IEnumerable<string?> candidates,
        IEnumerable<string?> protectedRoots)
    {
        var roots = protectedRoots
            .Where(root => !string.IsNullOrWhiteSpace(root))
            .Select(root => TryNormalizeDirectory(root!))
            .Where(root => root is not null)
            .Select(root => root!)
            .ToArray();

        var result = new List<string>();
        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                continue;
            }

            string full;
            try
            {
                full = Path.GetFullPath(candidate);
            }
            catch
            {
                continue;
            }

            if (roots.Any(root =>
                    full.StartsWith(root, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (!result.Contains(full, StringComparer.OrdinalIgnoreCase))
            {
                result.Add(full);
            }
        }

        return result;
    }

    private static string? TryNormalizeDirectory(string path)
    {
        try
        {
            var full = Path.GetFullPath(path)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return full + Path.DirectorySeparatorChar;
        }
        catch
        {
            return null;
        }
    }
}
