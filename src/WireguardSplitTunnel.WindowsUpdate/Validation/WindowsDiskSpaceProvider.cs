using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.WindowsUpdate.Validation;

public sealed class WindowsDiskSpaceProvider : IDiskSpaceProvider
{
    public long GetAvailableBytes(string path)
    {
        try
        {
            if (!WindowsLocalPath.TryGetCanonicalLocalDosPath(path, out var fullPath))
            {
                throw new IOException("The path is not a canonical local DOS path.");
            }
            var root = Path.GetPathRoot(fullPath);
            if (string.IsNullOrWhiteSpace(root))
            {
                throw new IOException("The path does not identify a drive.");
            }

            return new DriveInfo(root).AvailableFreeSpace;
        }
        catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new IOException("Unable to determine available disk space.", exception);
        }
    }
}
