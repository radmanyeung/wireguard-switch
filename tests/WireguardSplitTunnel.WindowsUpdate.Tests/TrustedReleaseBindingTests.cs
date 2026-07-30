using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class TrustedReleaseBindingTests
{
    private static readonly SemanticVersion Version =
        new(2, 0, 0);

    [Fact]
    public void TryCreate_BindsTheValidatedPackageToTheLiveApiDigestAndInvocationSource()
    {
        var archiveSha256 = Hash('a');

        var binding = TrustedReleaseBinding.TryCreate(
            Release(archiveSha256),
            Package(archiveSha256),
            PendingUpdateSource.Manual);

        binding.Should().NotBeNull();
        binding!.Version.Should().Be(Version);
        binding.ArchiveSha256.Should().Be(archiveSha256);
        binding.Source.Should().Be(PendingUpdateSource.Manual);
    }

    [Fact]
    public void TryCreate_RejectsAPackageWhoseArchiveDoesNotMatchTheLiveApiDigest()
    {
        var binding = TrustedReleaseBinding.TryCreate(
            Release(Hash('a')),
            Package(Hash('b')),
            PendingUpdateSource.Manual);

        binding.Should().BeNull();
    }

    private static SelectedWindowsRelease Release(
        string archiveSha256) =>
        new(
            Version,
            new Uri(
                "https://github.com/radmanyeung/"
                + "wireguard-switch/releases/download/v2.0.0/"
                + UpdateReleaseContract.WindowsAssetName),
            new Uri(
                "https://github.com/radmanyeung/"
                + "wireguard-switch/releases/download/v2.0.0/"
                + UpdateReleaseContract.WindowsChecksumAssetName),
            ArchiveSize: 100,
            archiveSha256);

    private static ValidatedUpdatePackage Package(
        string archiveSha256)
    {
        var manifest = new ReleaseManifest(
            schemaVersion: 1,
            Version.ToString(),
            UpdateReleaseContract.WindowsRuntimeIdentifier,
            minimumAutoUpdateVersion: "1.0.0",
            rollbackCompatibleFromVersion: "1.0.0",
            stateSchemaVersion: 1,
            UpdateReleaseContract.WindowsApplicationPath,
            UpdateReleaseContract.WindowsUpdaterPath,
            UpdateReleaseContract.RequiredLauncherPaths,
            [
                new ReleasePayloadFile(
                    UpdateReleaseContract.WindowsApplicationPath,
                    1,
                    Hash('c')),
                new ReleasePayloadFile(
                    UpdateReleaseContract.WindowsUpdaterPath,
                    1,
                    Hash('d'))
            ]);
        return new ValidatedUpdatePackage(
            Version,
            @"C:\Local\update.zip",
            @"C:\Local\release-manifest.json",
            archiveSha256,
            Hash('e'),
            @"C:\Local\candidate",
            ArchiveBytes: 100,
            ExpandedBytes: 200,
            RequiredDiskBytes: 300,
            manifest);
    }

    private static string Hash(char value) =>
        new(value, 64);
}
