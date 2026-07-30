namespace WireguardSplitTunnel.Core.Updates;

public sealed class StableReleaseSelector
{
    private readonly Func<Uri, string, string, bool> isInitialReleaseAssetUrl;

    public StableReleaseSelector()
        : this(GitHubReleaseUrlPolicy.IsValidInitialAssetUrl)
    {
    }

    internal StableReleaseSelector(Func<Uri, string, string, bool> isInitialReleaseAssetUrl)
    {
        this.isInitialReleaseAssetUrl = isInitialReleaseAssetUrl ?? throw new ArgumentNullException(nameof(isInitialReleaseAssetUrl));
    }

    public ReleaseSelectionResult Select(SemanticVersion currentVersion, GitHubReleaseMetadata? release)
    {
        if (release is null)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.MissingRelease);
        }

        if (release.Draft)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.Draft);
        }

        if (release.Prerelease)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.Prerelease);
        }

        if (!SemanticVersion.TryParseTag(release.TagName, out var version))
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.InvalidTag);
        }

        if (version.CompareTo(currentVersion) <= 0)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.NotNewer);
        }

        if (release.Assets is null)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.MissingAssets);
        }

        var archives = release.Assets.Where(asset => asset?.Name == UpdateReleaseContract.WindowsAssetName).ToList();
        var checksums = release.Assets.Where(asset => asset?.Name == UpdateReleaseContract.WindowsChecksumAssetName).ToList();
        if (archives.Count == 0)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.MissingArchiveAsset);
        }

        if (checksums.Count == 0)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.MissingChecksumAsset);
        }

        if (archives.Count != 1)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.DuplicateArchiveAsset);
        }

        if (checksums.Count != 1)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.DuplicateChecksumAsset);
        }

        var archive = archives[0]!;
        var checksum = checksums[0]!;
        if (archive.Size <= 0 || archive.Size > UpdateNetworkLimits.ArchiveBytes)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.InvalidArchiveSize);
        }

        if (checksum.Size <= 0 || checksum.Size > UpdateNetworkLimits.ChecksumBytes)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.InvalidChecksumSize);
        }

        if (!IsSha256(archive.Sha256))
        {
            return ReleaseSelectionResult.Rejected(
                ReleaseSelectionRejectionReason.InvalidArchiveDigest);
        }

        if (archive.BrowserDownloadUrl is null)
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.InvalidArchiveUrl);
        }

        if (checksum.BrowserDownloadUrl is null || !isInitialReleaseAssetUrl(checksum.BrowserDownloadUrl, release.TagName, checksum.Name))
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.InvalidChecksumUrl);
        }

        if (!isInitialReleaseAssetUrl(archive.BrowserDownloadUrl, release.TagName, archive.Name))
        {
            return ReleaseSelectionResult.Rejected(ReleaseSelectionRejectionReason.InvalidArchiveUrl);
        }

        return ReleaseSelectionResult.Selected(
            new SelectedWindowsRelease(
                version,
                archive.BrowserDownloadUrl,
                checksum.BrowserDownloadUrl,
                archive.Size,
                archive.Sha256!));
    }

    private static bool IsSha256(string? value) =>
        value is { Length: 64 }
        && value.All(character =>
            character is >= '0' and <= '9'
                or >= 'a' and <= 'f');
}
