namespace WireguardSplitTunnel.Core.Updates;

public sealed record GitHubReleaseAsset(
    string Name,
    Uri BrowserDownloadUrl,
    long Size,
    string? Sha256);

public sealed record GitHubReleaseMetadata
{
    public GitHubReleaseMetadata(string tagName, bool draft, bool prerelease, IReadOnlyList<GitHubReleaseAsset>? assets)
    {
        TagName = tagName;
        Draft = draft;
        Prerelease = prerelease;
        Assets = assets is null ? null : Array.AsReadOnly(assets.ToArray());
    }

    public string TagName { get; }
    public bool Draft { get; }
    public bool Prerelease { get; }
    public IReadOnlyList<GitHubReleaseAsset>? Assets { get; }
}

public sealed record SelectedWindowsRelease(
    SemanticVersion Version,
    Uri ArchiveUrl,
    Uri ChecksumUrl,
    long ArchiveSize,
    string ArchiveSha256);

public enum ReleaseSelectionRejectionReason
{
    MissingRelease,
    Draft,
    Prerelease,
    InvalidTag,
    NotNewer,
    MissingAssets,
    MissingArchiveAsset,
    MissingChecksumAsset,
    DuplicateArchiveAsset,
    DuplicateChecksumAsset,
    InvalidArchiveSize,
    InvalidChecksumSize,
    InvalidArchiveDigest,
    InvalidArchiveUrl,
    InvalidChecksumUrl
}

public sealed record ReleaseSelectionResult(
    SelectedWindowsRelease? Release,
    ReleaseSelectionRejectionReason? Rejection)
{
    public static ReleaseSelectionResult Selected(SelectedWindowsRelease release) => new(release, null);
    public static ReleaseSelectionResult Rejected(ReleaseSelectionRejectionReason rejection) => new(null, rejection);
}
