namespace WireguardSplitTunnel.Core.Updates;

public enum PendingUpdateSource
{
    Automatic,
    Manual
}

public sealed record LocalStagedUpdate(
    SemanticVersion Version,
    string ArchivePath,
    string ChecksumPath,
    string ManifestPath,
    string CandidateRoot,
    string ArchiveSha256,
    string NewManifestSha256,
    PendingUpdateSource Source);

public sealed record LocalUpdateMetadata(
    DateTimeOffset? LastAutomaticAttemptUtc = null,
    LocalStagedUpdate? StagedUpdate = null,
    string? LastError = null,
    bool ProtectedRemovalPending = false)
{
    public static LocalUpdateMetadata Empty { get; } = new();
}
