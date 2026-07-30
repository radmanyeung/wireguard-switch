namespace WireguardSplitTunnel.Core.Updates;

public static class UpdateNetworkLimits
{
    public const long MetadataBytes = 2L * 1024 * 1024;
    public const long ChecksumBytes = 4L * 1024;
    public const long ArchiveBytes = 256L * 1024 * 1024;
    public static readonly TimeSpan MetadataTimeout = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan NoProgressTimeout = TimeSpan.FromSeconds(60);
    public const int MaximumRedirects = 5;
}
