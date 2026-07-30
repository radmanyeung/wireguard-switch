using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Health;
using WireguardSplitTunnel.WindowsUpdate.Staging;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class WindowsUpdateRuntimeTests
{
    [Theory]
    [InlineData(UpdateHealthError.NoActiveTransaction)]
    [InlineData(UpdateHealthError.TransactionMismatch)]
    [InlineData(UpdateHealthError.WrongPhase)]
    [InlineData(UpdateHealthError.VersionMismatch)]
    public void MapHealthResult_NonMatchingStartupEvidence_IsBenign(
        UpdateHealthError error)
    {
        var mapped = WindowsUpdateRuntime.MapHealthResult(
            UpdateHealthResult.Failed(error));

        mapped.Outcome.Should().Be(
            UpdateStartupHealthOutcome.NoMatchingTransaction);
    }

    [Fact]
    public async Task ProductionPackageValidator_ForgedLayout_FailsBeforeChecksumIo()
    {
        using var root = new TemporaryDirectory();
        var paths = new LocalUpdatePaths(
            root.Path,
            new NeverReparse(),
            _ => DriveType.Fixed);
        var expected = paths.GetLayout(
            new SemanticVersion(2, 0, 0)).Layout!;
        var forged = new LocalUpdateLayout(
            expected.Version,
            expected.ProductRoot,
            expected.MetadataPath,
            expected.UpdatesRoot,
            expected.VersionRoot,
            expected.StagingRoot,
            expected.ArchivePath,
            Path.Combine(root.Path, "attacker-controlled.sha256"),
            expected.CandidateRoot,
            expected.ManifestPath);
        var validator =
            new WindowsUpdateRuntime.ProductionPackageValidator(
                paths,
                new SemanticVersion(1, 0, 0),
                currentManagedBytes: 4096);

        var result = await validator.ValidateAsync(
            expected.Version,
            forged,
            CancellationToken.None);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be(
            UpdatePackageValidationError.InvalidRequest);
    }

    [Fact]
    public void MapProtectedPreparationResult_CommittedBeforeMutexReleaseFailure_PreservesSuccess()
    {
        var prepared = ProtectedTransactionPreparationResult
            .Completed(
                new ProtectedTransactionId(
                    Guid.Parse(
                        "00112233-4455-6677-8899-aabbccddeeff")));

        var mapped = WindowsUpdateRuntime
            .MapProtectedPreparationResult(
                new ProtectedUpdateMutexResult(
                    ProtectedUpdateMutexStatus.ReleaseFailed,
                    ActionInvoked: true),
                prepared);

        mapped.Should().BeSameAs(prepared);
    }

    [Fact]
    public void MapProtectedPreparationResult_ActionNotInvokedNeverTrustsPreparedValue()
    {
        var prepared = ProtectedTransactionPreparationResult
            .Completed(
                new ProtectedTransactionId(
                    Guid.Parse(
                        "00112233-4455-6677-8899-aabbccddeeff")));

        var mapped = WindowsUpdateRuntime
            .MapProtectedPreparationResult(
                new ProtectedUpdateMutexResult(
                    ProtectedUpdateMutexStatus.SecurityMismatch,
                    ActionInvoked: false),
                prepared);

        mapped.Success.Should().BeFalse();
        mapped.Error.Should().Be(
            ProtectedTransactionPreparationError
                .ProtectedStorageFailed);
        mapped.DetailCode.Should().Be("protected_mutex");
    }

    private sealed class NeverReparse : IPathSafetyInspector
    {
        public bool IsReparsePoint(string path) => false;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "WireguardSplitTunnel.WindowsUpdate.Tests",
                Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
