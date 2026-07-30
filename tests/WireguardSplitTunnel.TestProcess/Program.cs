using System.Security;

namespace WireguardSplitTunnel.TestProcess;

internal static class Program
{
    private const int InvalidArgumentsExitCode = 64;
    private const string HealthMarkerName = "health.marker";
    private const string TestProcessDirectoryName = "WireguardSplitTunnel.TestProcess";
    private static readonly TimeSpan FailsafeTimeout = TimeSpan.FromMinutes(2);

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "wait")
        {
            await Task.Delay(FailsafeTimeout).ConfigureAwait(false);
            return 0;
        }

        if (args.Length == 1 && args[0] == "exit-before-health")
        {
            return 23;
        }

        if (args.Length == 2 && args[0] == "write-health-then-wait")
        {
            return await WriteHealthThenWaitAsync(args[1]).ConfigureAwait(false);
        }

        return InvalidArgumentsExitCode;
    }

    private static async Task<int> WriteHealthThenWaitAsync(string path)
    {
        if (!TryValidateHealthPath(path, out var canonicalPath))
        {
            return InvalidArgumentsExitCode;
        }

        try
        {
            await using var stream = new FileStream(
                canonicalPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                useAsync: true);

            var directory = Path.GetDirectoryName(canonicalPath);
            if (directory is null || !HasSafeExistingDirectoryChain(directory))
            {
                return InvalidArgumentsExitCode;
            }

            await stream.WriteAsync("healthy"u8.ToArray()).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
        }
        catch (Exception exception) when (IsExpectedPathFailure(exception))
        {
            return InvalidArgumentsExitCode;
        }

        await Task.Delay(FailsafeTimeout).ConfigureAwait(false);
        return 0;
    }

    private static bool TryValidateHealthPath(string path, out string canonicalPath)
    {
        canonicalPath = string.Empty;

        try
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            {
                return false;
            }

            var fullPath = Path.GetFullPath(path);
            if (!string.Equals(path, fullPath, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var directory = Path.GetDirectoryName(fullPath);
            var root = directory is null ? null : Path.GetDirectoryName(directory);
            var expectedRoot = Path.GetFullPath(Path.Combine(Path.GetTempPath(), TestProcessDirectoryName));

            if (directory is null
                || root is null
                || !string.Equals(fullPath, Path.Combine(directory, HealthMarkerName), StringComparison.OrdinalIgnoreCase)
                || !string.Equals(root, expectedRoot, StringComparison.OrdinalIgnoreCase)
                || !Guid.TryParseExact(Path.GetFileName(directory), "N", out _)
                || !HasSafeExistingDirectoryChain(directory))
            {
                return false;
            }

            if (File.Exists(fullPath) || Directory.Exists(fullPath))
            {
                return false;
            }

            canonicalPath = fullPath;
            return true;
        }
        catch (Exception exception) when (IsExpectedPathFailure(exception))
        {
            return false;
        }
    }

    private static bool HasSafeExistingDirectoryChain(string directory)
    {
        for (var current = directory; !string.IsNullOrEmpty(current);)
        {
            if (!Directory.Exists(current))
            {
                return false;
            }

            var attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.Directory) == 0
                || (attributes & FileAttributes.ReparsePoint) != 0)
            {
                return false;
            }

            var parent = Path.GetDirectoryName(current);
            if (string.IsNullOrEmpty(parent) || string.Equals(parent, current, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            current = parent;
        }

        return false;
    }

    private static bool IsExpectedPathFailure(Exception exception) =>
        exception is ArgumentException
            or IOException
            or UnauthorizedAccessException
            or NotSupportedException
            or SecurityException;
}
