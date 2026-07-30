using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class StableReleaseSelectorTests
{
    [Fact]
    public void Contracts_AreFixedToTheWindowsReleaseIdentity()
    {
        UpdateReleaseContract.Repository.Should().Be("radmanyeung/wireguard-switch");
        UpdateReleaseContract.LatestReleaseApiUri.Should().Be(new Uri("https://api.github.com/repos/radmanyeung/wireguard-switch/releases/latest"));
        UpdateReleaseContract.WindowsAssetName.Should().Be("wireguard-split-tunnel-win-x64.zip");
        UpdateReleaseContract.WindowsChecksumAssetName.Should().Be("wireguard-split-tunnel-win-x64.zip.sha256");
        UpdateReleaseContract.ReleaseManifestPath.Should().Be("release-manifest.json");
        UpdateReleaseContract.WindowsRuntimeIdentifier.Should().Be("win-x64");
        UpdateReleaseContract.WindowsApplicationPath.Should().Be("WireguardSplitTunnel/WireguardSplitTunnel.App.exe");
        UpdateReleaseContract.WindowsUpdaterPath.Should().Be("WireguardSplitTunnel/WireguardSplitTunnel.Updater.exe");
        UpdateReleaseContract.RequiredLauncherPaths.Should().Equal(
            "install.cmd", "start.cmd", "start-admin.cmd", "start-safe.cmd", "scripts/install.ps1", "scripts/start.ps1");
        UpdateReleaseContract.RedirectHosts.Should().Equal(
            "api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com");
    }

    [Fact]
    public void Limits_AreFixed()
    {
        UpdateNetworkLimits.MetadataBytes.Should().Be(2L * 1024 * 1024);
        UpdateNetworkLimits.ChecksumBytes.Should().Be(4L * 1024);
        UpdateNetworkLimits.ArchiveBytes.Should().Be(256L * 1024 * 1024);
        UpdateNetworkLimits.MetadataTimeout.Should().Be(TimeSpan.FromSeconds(30));
        UpdateNetworkLimits.DownloadTimeout.Should().Be(TimeSpan.FromMinutes(15));
        UpdateNetworkLimits.NoProgressTimeout.Should().Be(TimeSpan.FromSeconds(60));
        UpdateNetworkLimits.MaximumRedirects.Should().Be(5);
    }

    [Fact]
    public void Select_ReturnsNewerStableReleaseWithTheTwoExactAssets()
    {
        var archive = Asset(UpdateReleaseContract.WindowsAssetName, UpdateNetworkLimits.ArchiveBytes);
        var checksum = Asset(UpdateReleaseContract.WindowsChecksumAssetName, UpdateNetworkLimits.ChecksumBytes);
        var selector = new StableReleaseSelector(IsExpectedAssetUrl);

        var result = selector.Select(new SemanticVersion(1, 2, 3), Release("v1.2.4", assets: [archive, checksum]));

        result.Release.Should().Be(new SelectedWindowsRelease(
            new SemanticVersion(1, 2, 4),
            archive.BrowserDownloadUrl,
            checksum.BrowserDownloadUrl,
            archive.Size,
            archive.Sha256!));
        result.Rejection.Should().BeNull();
    }

    [Theory]
    [InlineData("v1.2.3", false, false, ReleaseSelectionRejectionReason.NotNewer)]
    [InlineData("v1.2.2", false, false, ReleaseSelectionRejectionReason.NotNewer)]
    [InlineData("invalid", false, false, ReleaseSelectionRejectionReason.InvalidTag)]
    [InlineData("v1.2.4", true, false, ReleaseSelectionRejectionReason.Draft)]
    [InlineData("v1.2.4", false, true, ReleaseSelectionRejectionReason.Prerelease)]
    public void Select_ReturnsTypedRejectionForUnacceptableRelease(string tag, bool draft, bool prerelease, ReleaseSelectionRejectionReason rejection)
    {
        var result = new StableReleaseSelector(IsExpectedAssetUrl).Select(
            new SemanticVersion(1, 2, 3),
            new GitHubReleaseMetadata(tag, draft, prerelease, [Asset(UpdateReleaseContract.WindowsAssetName), Asset(UpdateReleaseContract.WindowsChecksumAssetName)]));

        result.Release.Should().BeNull();
        result.Rejection.Should().Be(rejection);
    }

    [Fact]
    public void Select_RejectsNullReleaseOrAssetsWithoutThrowing()
    {
        var selector = new StableReleaseSelector(IsExpectedAssetUrl);

        selector.Select(new SemanticVersion(1, 2, 3), null).Rejection.Should().Be(ReleaseSelectionRejectionReason.MissingRelease);
        selector.Select(new SemanticVersion(1, 2, 3), new GitHubReleaseMetadata("v1.2.4", false, false, null!)).Rejection.Should().Be(ReleaseSelectionRejectionReason.MissingAssets);
    }

    [Fact]
    public void Metadata_SnapshotsAssetsAndSelectorHandlesNullAssetDataWithoutCallingValidator()
    {
        var assets = new List<GitHubReleaseAsset> { Asset(UpdateReleaseContract.WindowsAssetName), Asset(UpdateReleaseContract.WindowsChecksumAssetName) };
        var metadata = new GitHubReleaseMetadata("v1.2.4", false, false, assets);
        assets.Clear();
        new StableReleaseSelector().Select(new SemanticVersion(1, 2, 3), metadata).Release.Should().NotBeNull();

        var invoked = false;
        var injectedResult = new StableReleaseSelector((_, _, _) => { invoked = true; return true; }).Select(new SemanticVersion(1, 2, 3), new GitHubReleaseMetadata("v1.2.4", false, false,
        [new GitHubReleaseAsset(UpdateReleaseContract.WindowsAssetName, null!, 1, new string('a', 64)), Asset(UpdateReleaseContract.WindowsChecksumAssetName)]));

        injectedResult.Rejection.Should().Be(ReleaseSelectionRejectionReason.InvalidArchiveUrl);
       invoked.Should().BeFalse();

        var checksumValidatorInvoked = false;
        var checksumResult = new StableReleaseSelector((_, _, _) => { checksumValidatorInvoked = true; return true; }).Select(new SemanticVersion(1, 2, 3), new GitHubReleaseMetadata("v1.2.4", false, false,
        [Asset(UpdateReleaseContract.WindowsAssetName), new GitHubReleaseAsset(UpdateReleaseContract.WindowsChecksumAssetName, null!, 1, new string('a', 64))]));

        checksumResult.Rejection.Should().Be(ReleaseSelectionRejectionReason.InvalidChecksumUrl);
        checksumValidatorInvoked.Should().BeFalse();
        new StableReleaseSelector().Select(new SemanticVersion(1, 2, 3), new GitHubReleaseMetadata("v1.2.4", false, false,
        [null!, Asset(UpdateReleaseContract.WindowsAssetName), Asset(UpdateReleaseContract.WindowsChecksumAssetName)])).Release.Should().NotBeNull();
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    [InlineData((256L * 1024 * 1024) + 1L)]
    public void Select_RejectsInvalidArchiveSize(long size)
    {
        var result = SelectWithAssets(Asset(UpdateReleaseContract.WindowsAssetName, size), Asset(UpdateReleaseContract.WindowsChecksumAssetName));

        result.Rejection.Should().Be(ReleaseSelectionRejectionReason.InvalidArchiveSize);
    }

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    [InlineData((4L * 1024) + 1L)]
    public void Select_RejectsInvalidChecksumSize(long size)
    {
        var result = SelectWithAssets(Asset(UpdateReleaseContract.WindowsAssetName), Asset(UpdateReleaseContract.WindowsChecksumAssetName, size));

        result.Rejection.Should().Be(ReleaseSelectionRejectionReason.InvalidChecksumSize);
    }

    [Fact]
    public void Select_RejectsArchiveWithoutAnApiSha256Digest()
    {
        var archive = Asset(UpdateReleaseContract.WindowsAssetName) with
        {
            Sha256 = null
        };

        var result = SelectWithAssets(
            archive,
            Asset(UpdateReleaseContract.WindowsChecksumAssetName));

        result.Rejection.Should().Be(
            ReleaseSelectionRejectionReason.InvalidArchiveDigest);
    }

    [Fact]
    public void Select_RejectsMissingOrDuplicateRequiredAssetsAndUnexpectedInitialUrls()
    {
        SelectWithAssets(Asset(UpdateReleaseContract.WindowsAssetName)).Rejection.Should().Be(ReleaseSelectionRejectionReason.MissingChecksumAsset);
        SelectWithAssets(Asset(UpdateReleaseContract.WindowsChecksumAssetName)).Rejection.Should().Be(ReleaseSelectionRejectionReason.MissingArchiveAsset);
        SelectWithAssets(Asset(UpdateReleaseContract.WindowsAssetName), Asset(UpdateReleaseContract.WindowsAssetName), Asset(UpdateReleaseContract.WindowsChecksumAssetName)).Rejection.Should().Be(ReleaseSelectionRejectionReason.DuplicateArchiveAsset);
        SelectWithAssets(Asset(UpdateReleaseContract.WindowsAssetName), Asset(UpdateReleaseContract.WindowsChecksumAssetName), Asset(UpdateReleaseContract.WindowsChecksumAssetName)).Rejection.Should().Be(ReleaseSelectionRejectionReason.DuplicateChecksumAsset);
        SelectWithAssets(Asset(UpdateReleaseContract.WindowsAssetName, url: new Uri("https://invalid.example/archive.zip")), Asset(UpdateReleaseContract.WindowsChecksumAssetName)).Rejection.Should().Be(ReleaseSelectionRejectionReason.InvalidArchiveUrl);
    }

    private static ReleaseSelectionResult SelectWithAssets(params GitHubReleaseAsset[] assets) =>
        new StableReleaseSelector(IsExpectedAssetUrl).Select(new SemanticVersion(1, 2, 3), Release("v1.2.4", assets: assets));

    private static GitHubReleaseMetadata Release(string tag, bool draft = false, bool prerelease = false, IReadOnlyList<GitHubReleaseAsset>? assets = null) =>
        new(tag, draft, prerelease, assets ?? [Asset(UpdateReleaseContract.WindowsAssetName), Asset(UpdateReleaseContract.WindowsChecksumAssetName)]);

    private static GitHubReleaseAsset Asset(string name, long size = 1, Uri? url = null) =>
        new(
            name,
            url ?? new Uri($"https://github.com/radmanyeung/wireguard-switch/releases/download/v1.2.4/{name}"),
            size,
            new string('a', 64));

    private static bool IsExpectedAssetUrl(Uri url, string tag, string name) =>
        url.Scheme == Uri.UriSchemeHttps
        && url.Host == "github.com"
        && url.AbsolutePath == $"/radmanyeung/wireguard-switch/releases/download/{tag}/{name}";
}
