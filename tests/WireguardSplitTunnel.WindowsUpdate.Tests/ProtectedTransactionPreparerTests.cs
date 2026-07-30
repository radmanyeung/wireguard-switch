using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.Staging;
using WireguardSplitTunnel.WindowsUpdate.Transactions;
using WireguardSplitTunnel.WindowsUpdate.Validation;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class ProtectedTransactionPreparerTests
{
    [Fact]
    public async Task PrepareAsync_WithoutLiveMutexAuthority_FailsBeforeBoundaryWork()
    {
        var boundary = new RecordingPreparationBoundary();
        var sut = new ProtectedTransactionPreparer(
            boundary,
            new RecordingTransactionStoreGateway(),
            () => new ProtectedTransactionId(
                Guid.Parse("11111111-1111-1111-1111-111111111111")));

        var result = await sut.PrepareAsync(
            authority: null,
            request: null,
            CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(
            ProtectedTransactionPreparationError.InvalidAuthority);
        boundary.CallCount.Should().Be(0);
    }

    [Fact]
    public async Task PrepareAsync_WithMismatchedTrustedBinding_FailsBeforeBoundaryWork()
    {
        var fixture = new Fixture();
        var request = fixture.ValidRequest with
        {
            TrustedRelease = fixture.ValidRequest.TrustedRelease with
            {
                ArchiveSha256 = Hash('9')
            }
        };

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            request,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.InvalidRequest);
        fixture.Boundary.CallCount.Should().Be(0);
        fixture.Store.Events.Should().BeEmpty();
    }

    [Fact]
    public async Task PrepareAsync_WhenAlreadyCancelled_DoesNotStartBoundaryWork()
    {
        var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            cancellation.Token);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.Cancelled);
        fixture.Boundary.CallCount.Should().Be(0);
        fixture.Store.Events.Should().BeEmpty();
    }

    [Fact]
    public async Task PrepareAsync_WhenBoundaryReturnsFailureAfterCancellation_ReportsCancellation()
    {
        var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        fixture.Boundary.Handler = (_, _, _, _) =>
        {
            cancellation.Cancel();
            return Task.FromResult(
                ProtectedTransactionWorkspaceResult.Failed(
                    ProtectedTransactionPreparationError
                        .VerificationFailed,
                    "typed_failure"));
        };

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            cancellation.Token);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.Cancelled);
        fixture.Events.Should().Equal("boundary");
    }

    [Fact]
    public async Task PrepareAsync_WhenBoundaryReturnsWorkspaceAfterCancellation_CleansItBeforeReportingCancellation()
    {
        var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        fixture.Boundary.Handler = (_, _, _, _) =>
        {
            cancellation.Cancel();
            return Task.FromResult(
                ProtectedTransactionWorkspaceResult.Completed(
                    fixture.Workspace));
        };

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            cancellation.Token);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.Cancelled);
        fixture.Workspace.CleanupCalled.Should().BeTrue();
        fixture.Events.Should().Equal(
            "boundary",
            "cleanup",
            "dispose");
        fixture.Store.Events.Should().NotContain("create");
    }

    [Fact]
    public async Task PrepareAsync_WithAlreadyStaleAuthority_FailsBeforeBoundaryWork()
    {
        var fixture = new Fixture();
        fixture.Authority.Invalidate();

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.InvalidAuthority);
        fixture.Boundary.CallCount.Should().Be(0);
        fixture.Store.Events.Should().BeEmpty();
    }

    [Fact]
    public async Task PrepareAsync_HoldsAuthorityLeaseUntilEntirePreparationFinishes()
    {
        var fixture = new Fixture();
        var entered = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var boundary = new BlockingPreparationBoundary(
            fixture.Workspace,
            entered,
            release);
        var sut = new ProtectedTransactionPreparer(
            boundary,
            fixture.Store,
            () => fixture.TransactionId);

        var preparation = sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var invalidationStarted = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var invalidation = Task.Run(
            () =>
            {
                invalidationStarted.SetResult(true);
                fixture.Authority.Invalidate();
            });
        await invalidationStarted.Task.WaitAsync(
            TimeSpan.FromSeconds(5));

        await Task.Run(
                async () =>
                {
                    while (fixture.Authority.IsActive)
                    {
                        await Task.Delay(1);
                    }
                })
            .WaitAsync(TimeSpan.FromSeconds(5));
        invalidation.IsCompleted.Should().BeFalse();

        release.SetResult(true);
        var result = await preparation.WaitAsync(
            TimeSpan.FromSeconds(5));
        await invalidation.WaitAsync(TimeSpan.FromSeconds(5));

        result.Success.Should().BeTrue();
        fixture.Authority.IsActive.Should().BeFalse();
        fixture.Events.TakeLast(4).Should().Equal(
            "store-helper",
            "activate",
            "commit",
            "dispose");
    }

    [Fact]
    public async Task PrepareAsync_OnSuccess_VerifiesHelperAroundCreateAndActivatesPointerLast()
    {
        var fixture = new Fixture();

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Success.Should().BeTrue();
        result.TransactionId.Should().Be(fixture.TransactionId);
        fixture.Events.Should().Equal(
            "boundary",
            "helper",
            "create",
            "helper",
            "store-helper",
            "activate",
            "commit",
            "dispose");
        fixture.Store.CreatedMaterial!.Journal.Should().Be(
            new ProtectedJournalMetadata(
                ProtectedTransactionStore.JournalSchemaVersion,
                Generation: 0,
                Sha256: null));
        fixture.Store.CreatedRecord!.Phase.Should().Be(
            ProtectedTransactionPhase.ProtectedStaged);
        fixture.Store.CreatedRecord.AuthorizedProcess.Should().BeNull();
        fixture.Store.ActivatedRecord.Should().BeSameAs(
            fixture.Store.CreatedRecord);
    }

    [Fact]
    public async Task PrepareAsync_WhenStoreCreateFails_CleansExactUnactivatedWorkspace()
    {
        var fixture = new Fixture();
        fixture.Store.CreateError =
            ProtectedTransactionStoreError.AtomicWriteFailed;

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.StoreCreateFailed);
        fixture.Events.Should().Equal(
            "boundary",
            "helper",
            "create",
            "cleanup-gateway",
            "cleanup",
            "dispose");
        fixture.Store.ActivatedRecord.Should().BeNull();
        fixture.Store.CleanupExpectedMaterial.Should().BeSameAs(
            fixture.Workspace.Material);
    }

    [Fact]
    public async Task PrepareAsync_WhenCancelledAfterCreate_CleansThroughTheInactiveGateway()
    {
        var fixture = new Fixture();
        using var cancellation = new CancellationTokenSource();
        fixture.Store.AfterCreate =
            _ => cancellation.Cancel();

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            cancellation.Token);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.Cancelled);
        fixture.Events.Should().Equal(
            "boundary",
            "helper",
            "create",
            "cleanup-gateway",
            "cleanup",
            "dispose");
        fixture.Workspace.CleanupCalled.Should().BeTrue();
    }

    [Fact]
    public async Task PrepareAsync_WhenHelperChangesBeforeActivation_RefusesPointerAndCleans()
    {
        var fixture = new Fixture();
        fixture.Workspace.HelperVerificationResults.Clear();
        fixture.Workspace.HelperVerificationResults.Enqueue(true);
        fixture.Workspace.HelperVerificationResults.Enqueue(false);

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.HelperVerificationFailed);
        fixture.Events.Should().Equal(
            "boundary",
            "helper",
            "create",
            "helper",
            "cleanup-gateway",
            "cleanup",
            "dispose");
        fixture.Store.ActivatedRecord.Should().BeNull();
    }

    [Fact]
    public async Task PrepareAsync_WhenExternalActivationWinsAfterCreate_PreservesTheActiveWorkspace()
    {
        var fixture = new Fixture();
        fixture.Workspace.HelperVerificationResults.Clear();
        fixture.Workspace.HelperVerificationResults.Enqueue(true);
        fixture.Workspace.HelperVerificationResults.Enqueue(false);
        fixture.Store.AfterCreate =
            store =>
            {
                store.Events.Add("external-activate");
                store.ActiveTransactionId =
                    fixture.TransactionId;
                store.CleanupError =
                    ProtectedTransactionStoreError.Conflict;
            };

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError
                .HelperVerificationFailed);
        result.DetailCode.Should().Be("before_activation");
        fixture.Store.ActiveTransactionId.Should().Be(
            fixture.TransactionId);
        fixture.Store.CleanupCallbackInvoked.Should().BeFalse();
        fixture.Workspace.CleanupCalled.Should().BeFalse();
        fixture.Events.Should().Equal(
            "boundary",
            "helper",
            "create",
            "external-activate",
            "helper",
            "cleanup-gateway",
            "dispose");
    }

    [Fact]
    public async Task PrepareAsync_WhenHelperFailsBeforeCreate_CleansThroughTheInactiveGateway()
    {
        var fixture = new Fixture();
        fixture.Workspace.HelperVerificationResults.Clear();
        fixture.Workspace.HelperVerificationResults.Enqueue(false);

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError
                .HelperVerificationFailed);
        fixture.Events.Should().Equal(
            "boundary",
            "helper",
            "cleanup-gateway",
            "cleanup",
            "dispose");
        fixture.Store.CleanupCallbackInvoked.Should().BeTrue();
    }

    [Fact]
    public async Task PrepareAsync_WhenWorkspaceMaterialHasNoValidTransactionId_CleansDirectly()
    {
        var fixture = new Fixture(
            _ => Material(default));

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError
                .VerificationFailed);
        result.DetailCode.Should().Be("material_binding");
        fixture.Events.Should().Equal(
            "boundary",
            "cleanup",
            "dispose");
        fixture.Store.CleanupCallbackInvoked.Should().BeFalse();
        fixture.Workspace.CleanupCalled.Should().BeTrue();
    }

    [Fact]
    public async Task PrepareAsync_WhenPointerActivationFails_CleansAndNeverCommitsWorkspace()
    {
        var fixture = new Fixture();
        fixture.Store.ActivateError =
            ProtectedTransactionStoreError.AtomicWriteFailed;

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.ActivationFailed);
        fixture.Events.Should().Equal(
            "boundary",
            "helper",
            "create",
            "helper",
            "store-helper",
            "activate",
            "cleanup-gateway",
            "cleanup",
            "dispose");
        fixture.Workspace.CommitCalled.Should().BeFalse();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PrepareAsync_ReplacementCancellationLeavesOldActiveAndCleansOnlyNew(
        bool sameVersionManualPromotion)
    {
        var fixture = ReplacementFixture(
            sameVersionManualPromotion);
        var oldTransactionId = new ProtectedTransactionId(
            Guid.Parse(
                "22222222-2222-2222-2222-222222222222"));
        var request = ReplacementRequest(
            fixture,
            oldTransactionId,
            sameVersionManualPromotion);
        fixture.Store.ActiveTransactionId = oldTransactionId;
        using var cancellation = new CancellationTokenSource();
        fixture.Store.AfterCreate = _ => cancellation.Cancel();

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            request,
            cancellation.Token);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.Cancelled);
        fixture.Store.ActiveTransactionId.Should().Be(
            oldTransactionId);
        fixture.Workspace.CleanupCalled.Should().BeTrue();
        fixture.Store.CleanedSupersededTransactionIds
            .Should().BeEmpty();
    }

    [Fact]
    public async Task PrepareAsync_CancelledAfterHelperVerificationDoesNotSwapExpectedOldPointer()
    {
        var fixture = ReplacementFixture(
            sameVersionManualPromotion: false);
        var oldTransactionId = new ProtectedTransactionId(
            Guid.Parse(
                "22222222-2222-2222-2222-222222222222"));
        var request = ReplacementRequest(
            fixture,
            oldTransactionId,
            sameVersionManualPromotion: false);
        fixture.Store.ActiveTransactionId = oldTransactionId;
        using var cancellation = new CancellationTokenSource();
        fixture.Store.AfterVerify = _ => cancellation.Cancel();

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            request,
            cancellation.Token);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.Cancelled);
        fixture.Store.ActiveTransactionId.Should().Be(
            oldTransactionId);
        fixture.Workspace.CleanupCalled.Should().BeTrue();
        fixture.Events.Should().NotContain("activate");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PrepareAsync_ReplacementActivationFailureLeavesOldActiveAndCleansOnlyNew(
        bool sameVersionManualPromotion)
    {
        var fixture = ReplacementFixture(
            sameVersionManualPromotion);
        var oldTransactionId = new ProtectedTransactionId(
            Guid.Parse(
                "22222222-2222-2222-2222-222222222222"));
        var request = ReplacementRequest(
            fixture,
            oldTransactionId,
            sameVersionManualPromotion);
        fixture.Store.ActiveTransactionId = oldTransactionId;
        fixture.Store.ActivateError =
            ProtectedTransactionStoreError.Conflict;

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            request,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.ActivationFailed);
        fixture.Store.ActiveTransactionId.Should().Be(
            oldTransactionId);
        fixture.Workspace.CleanupCalled.Should().BeTrue();
        fixture.Store.CleanedSupersededTransactionIds
            .Should().BeEmpty();
    }

    [Fact]
    public async Task PrepareAsync_SameVersionManualPromotionSwapsBeforeCleaningOldWorkspace()
    {
        var fixture = ReplacementFixture(
            sameVersionManualPromotion: true);
        var oldTransactionId = new ProtectedTransactionId(
            Guid.Parse(
                "22222222-2222-2222-2222-222222222222"));
        var request = ReplacementRequest(
            fixture,
            oldTransactionId,
            sameVersionManualPromotion: true);
        fixture.Store.ActiveTransactionId = oldTransactionId;

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            request,
            CancellationToken.None);

        result.Success.Should().BeTrue();
        fixture.Store.ActiveTransactionId.Should().Be(
            fixture.TransactionId);
        fixture.Store.CleanedSupersededTransactionIds
            .Should().Equal(oldTransactionId);
        fixture.Events.Should().ContainInOrder(
            "activate",
            "commit",
            "cleanup-superseded");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PrepareAsync_WhenSupersededCleanupFails_RecordsBoundedPendingCleanupWithoutChangingCommittedPointer(
        bool throws)
    {
        var fixture = ReplacementFixture(
            sameVersionManualPromotion: true);
        var oldId = new ProtectedTransactionId(
            Guid.Parse(
                "22222222-2222-2222-2222-222222222222"));
        var request = ReplacementRequest(
            fixture,
            oldId,
            sameVersionManualPromotion: true);
        fixture.Store.ActiveTransactionId = oldId;
        fixture.Store.CleanupError =
            ProtectedTransactionStoreError.IoFailure;
        fixture.Store.ThrowOnSupersededCleanup = throws;

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            request,
            CancellationToken.None);

        result.Success.Should().BeTrue();
        result.TransactionId.Should().Be(fixture.TransactionId);
        result.DetailCode.Should().Be(
            "superseded_cleanup_pending");
        fixture.Store.ActiveTransactionId.Should().Be(
            fixture.TransactionId);
        fixture.Events.Count(
                entry => entry == "cleanup-superseded")
            .Should().Be(2);
        fixture.Events.Should().ContainInOrder(
            "activate",
            "commit",
            "cleanup-superseded");
    }

    [Fact]
    public async Task PrepareAsync_WhenCleanupCannotProveOwnership_ReturnsCleanupFailure()
    {
        var fixture = new Fixture();
        fixture.Store.CreateError =
            ProtectedTransactionStoreError.AtomicWriteFailed;
        fixture.Workspace.CleanupResult = false;

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.CleanupFailed);
        fixture.Workspace.CommitCalled.Should().BeFalse();
    }

    [Fact]
    public async Task PrepareAsync_WhenCommitThrowsAfterActivation_PreservesActiveWorkspace()
    {
        var fixture = new Fixture();
        fixture.Workspace.ThrowOnCommit = true;

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Error.Should().Be(
            ProtectedTransactionPreparationError.VerificationFailed);
        fixture.Store.ActivatedRecord.Should().NotBeNull();
        fixture.Workspace.CleanupCalled.Should().BeFalse();
        fixture.Events.Should().Equal(
            "boundary",
            "helper",
            "create",
            "helper",
            "store-helper",
            "activate",
            "commit",
            "dispose");
    }

    [Fact]
    public async Task PrepareAsync_WhenActivationOutcomeIsAmbiguous_PreservesWorkspace()
    {
        var fixture = new Fixture();
        fixture.Store.ActivateError =
            ProtectedTransactionStoreError.AtomicWriteFailed;
        fixture.Store.CleanupError =
            ProtectedTransactionStoreError.CorruptData;

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.CleanupFailed);
        fixture.Workspace.CleanupCalled.Should().BeFalse();
    }

    [Fact]
    public async Task PrepareAsync_WhenFailedActivationPointsAtThisTransaction_PreservesWorkspace()
    {
        var fixture = new Fixture();
        fixture.Store.ActivateError =
            ProtectedTransactionStoreError.AtomicWriteFailed;
        fixture.Store.CleanupError =
            ProtectedTransactionStoreError.Conflict;
        fixture.Store.ActiveTransactionId =
            fixture.TransactionId;

        var result = await fixture.Sut.PrepareAsync(
            fixture.Authority,
            fixture.ValidRequest,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.ActivationFailed);
        fixture.Workspace.CleanupCalled.Should().BeFalse();
        fixture.Workspace.CommitCalled.Should().BeFalse();
    }

    [Fact]
    public void ProtectedDiskPolicy_AcceptsExactBoundary()
    {
        var limits = UpdatePackageLimits.Default;
        var required = checked(
            10L + 20L + 30L + limits.ReserveBytes);

        var result = ProtectedPreparationDiskPolicy.Evaluate(
            required,
            required,
            archiveBytes: 10,
            expandedCandidateBytes: 20,
            currentManagedBytes: 30,
            limits);

        result.Success.Should().BeTrue();
        result.RequiredBytes.Should().Be(required);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ProtectedDiskPolicy_RejectsEitherVolumeOneByteShort(
        bool programDataIsShort)
    {
        var limits = UpdatePackageLimits.Default;
        var required = checked(
            10L + 20L + 30L + limits.ReserveBytes);

        var result = ProtectedPreparationDiskPolicy.Evaluate(
            programDataIsShort ? required - 1 : required,
            programDataIsShort ? required : required - 1,
            archiveBytes: 10,
            expandedCandidateBytes: 20,
            currentManagedBytes: 30,
            limits);

        result.Success.Should().BeFalse();
        result.ErrorCode.Should().Be(
            UpdateDiskSpaceError.InsufficientSpace);
        result.RequiredBytes.Should().Be(required);
    }

    [Fact]
    public async Task ProductionBoundary_WhenNotElevated_DoesNotReadLocalOrInstalledState()
    {
        var fixture = new BoundaryFixture();
        fixture.Environment.Elevated = false;

        var result = await fixture.Boundary.PrepareAsync(
            fixture.Authority,
            fixture.Request,
            fixture.TransactionId,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.NotElevated);
        fixture.InstalledLocator.CallCount.Should().Be(0);
        fixture.ArtifactBuilder.CallCount.Should().Be(0);
    }

    [Fact]
    public async Task ProductionBoundary_RejectsForgedPersistedLocalPaths()
    {
        var fixture = new BoundaryFixture();
        var request = fixture.Request with
        {
            StagedUpdate = fixture.Request.StagedUpdate with
            {
                CandidateRoot = @"C:\attacker\candidate"
            }
        };

        var result = await fixture.Boundary.PrepareAsync(
            fixture.Authority,
            request,
            fixture.TransactionId,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.UnsafeLocalStaging);
        fixture.InstalledLocator.CallCount.Should().Be(0);
        fixture.ArtifactBuilder.CallCount.Should().Be(0);
    }

    [Fact]
    public async Task ProductionBoundary_RejectsUncLocalAuthority()
    {
        var fixture = new BoundaryFixture(
            localRoot: @"\\server\share\LocalAppData");

        var result = await fixture.Boundary.PrepareAsync(
            fixture.Authority,
            fixture.Request,
            fixture.TransactionId,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError.UnsafeLocalStaging);
        fixture.ArtifactBuilder.CallCount.Should().Be(0);
    }

    [Fact]
    public async Task ProductionBoundary_RejectsUnavailableInstalledReleaseBeforeCopy()
    {
        var fixture = new BoundaryFixture();
        fixture.InstalledLocator.Location =
            InstalledReleaseLocation.Unavailable(
                "developer_build");

        var result = await fixture.Boundary.PrepareAsync(
            fixture.Authority,
            fixture.Request,
            fixture.TransactionId,
            CancellationToken.None);

        result.Error.Should().Be(
            ProtectedTransactionPreparationError
                .InstalledReleaseUnavailable);
        fixture.ArtifactBuilder.CallCount.Should().Be(0);
    }

    [Fact]
    public async Task ProductionBoundary_CancellationAfterArtifactVerificationResultWinsBeforeMapping()
    {
        var fixture = new BoundaryFixture();
        using var cancellation = new CancellationTokenSource();
        fixture.ArtifactBuilder.AfterBuild = cancellation.Cancel;

        await FluentActions.Awaiting(
                () => fixture.Boundary.PrepareAsync(
                    fixture.Authority,
                    fixture.Request,
                    fixture.TransactionId,
                    cancellation.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public void PreparationPinnedFile_HoldsAncestorDirectoriesAndRevalidatesFullIdentity()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "WireguardSplitTunnel-Preparer-"
                + Guid.NewGuid().ToString("N"));
        var candidate = Path.Combine(root, "candidate");
        var nested = Path.Combine(candidate, "nested");
        var file = Path.Combine(nested, "payload.bin");
        var moved = Path.Combine(candidate, "renamed");
        Directory.CreateDirectory(nested);
        File.WriteAllBytes(file, [1, 2, 3, 4]);

        try
        {
            var inspector = new NeverReparseInspector();
            PreparationPinnedDirectory.TryOpen(
                    candidate,
                    inspector,
                    out var rootLease)
                .Should().BeTrue();
            using (rootLease)
            {
                PreparationPinnedFile.TryOpen(
                        rootLease!,
                        file,
                        maximumBytes: 4,
                        inspector,
                        out var pinned)
                    .Should().BeTrue();
                using (pinned)
                {
                    pinned!.Identity.VolumeSerialNumber
                        .Should().NotBe(0);
                    (pinned.Identity.FileIdLow != 0
                        || pinned.Identity.FileIdHigh != 0)
                        .Should().BeTrue();
                    pinned.Revalidate().Should().BeTrue();

                    var write = () =>
                        File.WriteAllBytes(file, [9]);
                    write.Should().Throw<IOException>();

                    var move = () =>
                        Directory.Move(nested, moved);
                    move.Should().Throw<IOException>();
                    pinned.Revalidate().Should().BeTrue();
                }
            }

            Directory.Move(nested, moved);
            Directory.Exists(moved).Should().BeTrue();
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public void PreparationPinnedFile_RejectsPathOutsideRetainedRoot()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "WireguardSplitTunnel-Preparer-"
                + Guid.NewGuid().ToString("N"));
        var retained = Path.Combine(root, "retained");
        var outside = Path.Combine(root, "outside.bin");
        Directory.CreateDirectory(retained);
        File.WriteAllBytes(outside, [1]);

        try
        {
            var inspector = new NeverReparseInspector();
            PreparationPinnedDirectory.TryOpen(
                    retained,
                    inspector,
                    out var rootLease)
                .Should().BeTrue();
            using (rootLease)
            {
                PreparationPinnedFile.TryOpen(
                        rootLease!,
                        outside,
                        maximumBytes: 1,
                        inspector,
                        out var pinned)
                    .Should().BeFalse();
                pinned.Should().BeNull();
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void RetainedProductVersionVerifier_UsesStreamOverloadAndNeverPathOverload()
    {
        var reader = new StreamOnlyProductVersionReader(
            "2.0.0");
        using var stream = new MemoryStream([1, 2, 3]);

        var result = RetainedProductVersionVerifier.Matches(
            reader,
            stream,
            new SemanticVersion(2, 0, 0),
            revalidate: () => true);

        result.Should().BeTrue();
        reader.StreamCalls.Should().Be(1);
        reader.PathCalls.Should().Be(0);
    }

    private sealed class Fixture
    {
        public Fixture(
            Func<
                ProtectedTransactionId,
                ProtectedStagedTransactionMaterial>?
                materialFactory = null)
        {
            Boundary = new RecordingPreparationBoundary();
            Store = new RecordingTransactionStoreGateway();
            Events = [];
            Boundary.Events = Events;
            Store.Events = Events;
            TransactionId = new ProtectedTransactionId(
                Guid.Parse("11111111-1111-1111-1111-111111111111"));
            Workspace = new RecordingWorkspace(
                (materialFactory ?? Material)(TransactionId),
                Events);
            Boundary.Result =
                ProtectedTransactionWorkspaceResult.Completed(Workspace);
            Sut = new ProtectedTransactionPreparer(
                Boundary,
                Store,
                () => TransactionId);
            Authority = new ProtectedUpdateMutexContext(
                wasAbandoned: false);
            ValidRequest = Request();
        }

        public List<string> Events { get; }
        public RecordingPreparationBoundary Boundary { get; }
        public RecordingTransactionStoreGateway Store { get; }
        public RecordingWorkspace Workspace { get; }
        public ProtectedTransactionId TransactionId { get; }
        public ProtectedTransactionPreparer Sut { get; }
        public ProtectedUpdateMutexContext Authority { get; }
        public ProtectedTransactionPreparationRequest ValidRequest { get; }

        private static ProtectedTransactionPreparationRequest Request()
        {
            var version = new SemanticVersion(2, 0, 0);
            var archiveHash = Hash('a');
            var manifestHash = Hash('b');
            var staged = new LocalStagedUpdate(
                version,
                @"C:\Users\user\AppData\Local\WireguardSplitTunnel\updates\2.0.0\staging\wireguard-split-tunnel-win-x64.zip",
                @"C:\Users\user\AppData\Local\WireguardSplitTunnel\updates\2.0.0\staging\wireguard-split-tunnel-win-x64.zip.sha256",
                @"C:\Users\user\AppData\Local\WireguardSplitTunnel\updates\2.0.0\candidate\release-manifest.json",
                @"C:\Users\user\AppData\Local\WireguardSplitTunnel\updates\2.0.0\candidate",
                archiveHash,
                manifestHash,
                PendingUpdateSource.Automatic);
            return new ProtectedTransactionPreparationRequest(
                staged,
                new TrustedReleaseBinding(
                    version,
                    archiveHash,
                    manifestHash,
                    PendingUpdateSource.Automatic),
                SupportedStateSchemaVersion: 1,
                UpdatePackageLimits.Default);
        }
    }

    private static Fixture ReplacementFixture(
        bool sameVersionManualPromotion) =>
        new(
            transactionId => Material(transactionId) with
            {
                Source = sameVersionManualPromotion
                    ? PendingUpdateSource.Manual
                    : PendingUpdateSource.Automatic
            });

    private static ProtectedTransactionPreparationRequest
        ReplacementRequest(
            Fixture fixture,
            ProtectedTransactionId oldTransactionId,
            bool sameVersionManualPromotion)
    {
        var source = sameVersionManualPromotion
            ? PendingUpdateSource.Manual
            : PendingUpdateSource.Automatic;
        var request = fixture.ValidRequest with
        {
            StagedUpdate = fixture.ValidRequest.StagedUpdate with
            {
                Source = source
            },
            TrustedRelease = fixture.ValidRequest.TrustedRelease with
            {
                Source = source
            },
            ExpectedActive =
                new ProtectedActiveTransactionExpectation(
                    oldTransactionId,
                    sameVersionManualPromotion
                        ? new SemanticVersion(2, 0, 0)
                        : new SemanticVersion(1, 5, 0),
                    PendingUpdateSource.Automatic)
        };
        return request;
    }

    private sealed class BoundaryFixture
    {
        public BoundaryFixture(
            string localRoot = @"C:\Users\user\AppData\Local")
        {
            var inspector = new NeverReparseInspector();
            var localPaths = new LocalUpdatePaths(
                localRoot,
                inspector,
                _ => DriveType.Fixed);
            var protectedPaths =
                new ProtectedTransactionPaths(
                    @"C:\ProgramData\WireguardSplitTunnel",
                    inspector,
                    _ => DriveType.Fixed);
            var version = new SemanticVersion(2, 0, 0);
            var layout = localPaths.GetLayout(version).Layout;
            var staged = layout is null
                ? new LocalStagedUpdate(
                    version,
                    @"C:\invalid\archive.zip",
                    @"C:\invalid\archive.sha256",
                    @"C:\invalid\release-manifest.json",
                    @"C:\invalid\candidate",
                    Hash('a'),
                    Hash('b'),
                    PendingUpdateSource.Automatic)
                : new LocalStagedUpdate(
                    version,
                    layout.ArchivePath,
                    layout.ChecksumPath,
                    layout.ManifestPath,
                    layout.CandidateRoot,
                    Hash('a'),
                    Hash('b'),
                    PendingUpdateSource.Automatic);
            Request = new ProtectedTransactionPreparationRequest(
                staged,
                new TrustedReleaseBinding(
                    version,
                    Hash('a'),
                    Hash('b'),
                    PendingUpdateSource.Automatic),
                1,
                UpdatePackageLimits.Default);
            Environment = new RecordingEnvironment();
            InstalledLocator =
                new RecordingInstalledReleaseLocator();
            ArtifactBuilder =
                new RecordingArtifactBuilder();
            Boundary =
                new WindowsProtectedTransactionPreparationBoundary(
                    localPaths,
                    protectedPaths,
                    Environment,
                    InstalledLocator,
                    ArtifactBuilder);
            TransactionId = new ProtectedTransactionId(
                Guid.Parse(
                    "22222222-2222-2222-2222-222222222222"));
            Authority = new ProtectedUpdateMutexContext(false);
        }

        public WindowsProtectedTransactionPreparationBoundary
            Boundary
        { get; }
        public RecordingEnvironment Environment { get; }
        public RecordingInstalledReleaseLocator
            InstalledLocator
        { get; }
        public RecordingArtifactBuilder ArtifactBuilder { get; }
        public ProtectedTransactionPreparationRequest Request { get; }
        public ProtectedTransactionId TransactionId { get; }
        public ProtectedUpdateMutexContext Authority { get; }
    }

    private sealed class RecordingPreparationBoundary
        : IProtectedTransactionPreparationBoundary
    {
        public int CallCount { get; private set; }
        public List<string>? Events { get; set; }
        public ProtectedTransactionWorkspaceResult? Result { get; set; }
        public Func<
            ProtectedUpdateMutexContext,
            ProtectedTransactionPreparationRequest,
            ProtectedTransactionId,
            CancellationToken,
            Task<ProtectedTransactionWorkspaceResult>>? Handler
        {
            get;
            set;
        }

        public Task<ProtectedTransactionWorkspaceResult> PrepareAsync(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionPreparationRequest request,
            ProtectedTransactionId transactionId,
            CancellationToken cancellationToken)
        {
            CallCount++;
            Events?.Add("boundary");
            if (Handler is not null)
            {
                return Handler(
                    authority,
                    request,
                    transactionId,
                    cancellationToken);
            }

            return Task.FromResult(
                Result
                ?? throw new InvalidOperationException(
                    "No boundary result was configured."));
        }
    }

    private sealed class BlockingPreparationBoundary
        : IProtectedTransactionPreparationBoundary
    {
        private readonly IProtectedTransactionPreparationWorkspace
            _workspace;
        private readonly TaskCompletionSource<bool> _entered;
        private readonly TaskCompletionSource<bool> _release;

        public BlockingPreparationBoundary(
            IProtectedTransactionPreparationWorkspace workspace,
            TaskCompletionSource<bool> entered,
            TaskCompletionSource<bool> release)
        {
            _workspace = workspace;
            _entered = entered;
            _release = release;
        }

        public async Task<ProtectedTransactionWorkspaceResult>
            PrepareAsync(
                ProtectedUpdateMutexContext authority,
                ProtectedTransactionPreparationRequest request,
                ProtectedTransactionId transactionId,
                CancellationToken cancellationToken)
        {
            _entered.SetResult(true);
            await _release.Task.WaitAsync(cancellationToken);
            return ProtectedTransactionWorkspaceResult.Completed(
                _workspace);
        }
    }

    private sealed class RecordingTransactionStoreGateway
        : IProtectedTransactionStoreGateway
    {
        public List<string> Events { get; set; } = [];
        public ProtectedTransactionStoreError CreateError { get; set; }
        public ProtectedTransactionStoreError VerifyHelperError { get; set; }
        public ProtectedTransactionStoreError ActivateError { get; set; }
        public ProtectedTransactionStoreError CleanupError { get; set; }
        public bool ThrowOnSupersededCleanup { get; set; }
        public Action<RecordingTransactionStoreGateway>? AfterCreate
        {
            get;
            set;
        }
        public Action<RecordingTransactionStoreGateway>? AfterVerify
        {
            get;
            set;
        }
        public ProtectedTransactionId? ActiveTransactionId
        {
            get;
            set;
        }
        public bool CleanupCallbackInvoked { get; private set; }
        public ProtectedStagedTransactionMaterial?
            CleanupExpectedMaterial
        {
            get;
            private set;
        }
        public ProtectedStagedTransactionMaterial? CreatedMaterial { get; private set; }
        public ProtectedTransactionRecord? CreatedRecord { get; private set; }
        public ProtectedTransactionRecord? ActivatedRecord { get; private set; }
        public List<ProtectedTransactionId>
            CleanedSupersededTransactionIds
        {
            get;
        } = [];

        public ProtectedTransactionWriteResult CreateProtectedStaged(
            ProtectedUpdateMutexContext authority,
            ProtectedStagedTransactionMaterial material)
        {
            Events.Add("create");
            CreatedMaterial = material;
            if (CreateError != ProtectedTransactionStoreError.None)
            {
                return new ProtectedTransactionWriteResult(
                    false,
                    null,
                    CreateError);
            }

            CreatedRecord = new ProtectedTransactionRecord(
                ProtectedTransactionStore.TransactionSchemaVersion,
                material.TransactionId,
                material.Version,
                material.Source,
                material.InstalledRelease,
                material.Candidate,
                material.HelperSha256,
                ProtectedTransactionPhase.ProtectedStaged,
                AuthorizedProcess: null,
                material.Journal);
            AfterCreate?.Invoke(this);
            return new ProtectedTransactionWriteResult(
                true,
                CreatedRecord,
                ProtectedTransactionStoreError.None);
        }

        public ProtectedTransactionStoreResult VerifyHelper(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionId transactionId,
            string expectedSha256)
        {
            Events.Add("store-helper");
            var result = new ProtectedTransactionStoreResult(
                VerifyHelperError == ProtectedTransactionStoreError.None,
                VerifyHelperError);
            AfterVerify?.Invoke(this);
            return result;
        }

        public ProtectedTransactionStoreResult Activate(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionRecord expectedRecord,
            ProtectedActiveTransactionExpectation? expectedActive)
        {
            Events.Add("activate");
            if (ActivateError == ProtectedTransactionStoreError.None)
            {
                ActivatedRecord = expectedRecord;
                ActiveTransactionId = expectedRecord.TransactionId;
            }

            return new ProtectedTransactionStoreResult(
                ActivateError == ProtectedTransactionStoreError.None,
                ActivateError);
        }

        public ProtectedTransactionStoreResult
            CleanupInactiveTransaction(
                ProtectedUpdateMutexContext authority,
                ProtectedStagedTransactionMaterial
                    expectedMaterial,
                Func<bool> cleanup)
        {
            Events.Add("cleanup-gateway");
            CleanupExpectedMaterial = expectedMaterial;
            if (CleanupError
                != ProtectedTransactionStoreError.None)
            {
                return new ProtectedTransactionStoreResult(
                    false,
                    CleanupError);
            }

            CleanupCallbackInvoked = true;
            var success = cleanup();
            return new ProtectedTransactionStoreResult(
                success,
                success
                    ? ProtectedTransactionStoreError.None
                    : ProtectedTransactionStoreError.IoFailure);
        }

        public ProtectedTransactionStoreResult
            CleanupSupersededTransaction(
                ProtectedUpdateMutexContext authority,
                ProtectedActiveTransactionExpectation expectedActive,
                Func<bool> cleanup)
        {
            Events.Add("cleanup-superseded");
            if (ThrowOnSupersededCleanup)
            {
                throw new IOException(
                    "superseded cleanup failed");
            }
            if (ActiveTransactionId
                    == expectedActive.TransactionId
                || CleanupError
                    != ProtectedTransactionStoreError.None)
            {
                return new ProtectedTransactionStoreResult(
                    false,
                    ActiveTransactionId
                            == expectedActive.TransactionId
                        ? ProtectedTransactionStoreError.Conflict
                        : CleanupError);
            }

            var success = cleanup();
            if (success)
            {
                CleanedSupersededTransactionIds.Add(
                    expectedActive.TransactionId);
            }

            return new ProtectedTransactionStoreResult(
                success,
                success
                    ? ProtectedTransactionStoreError.None
                    : ProtectedTransactionStoreError.IoFailure);
        }
    }

    private sealed class RecordingWorkspace
        : IProtectedTransactionPreparationWorkspace
    {
        private readonly List<string> _events;

        public RecordingWorkspace(
            ProtectedStagedTransactionMaterial material,
            List<string> events)
        {
            Material = material;
            _events = events;
            HelperVerificationResults.Enqueue(true);
            HelperVerificationResults.Enqueue(true);
        }

        public ProtectedStagedTransactionMaterial Material { get; }
        public Queue<bool> HelperVerificationResults { get; } = new();
        public bool CleanupResult { get; set; } = true;
        public bool CleanupCalled { get; private set; }
        public bool CommitCalled { get; private set; }
        public bool ThrowOnCommit { get; set; }

        public bool VerifyHelperIdentity()
        {
            _events.Add("helper");
            return HelperVerificationResults.Dequeue();
        }

        public bool TryCleanup()
        {
            CleanupCalled = true;
            _events.Add("cleanup");
            return CleanupResult;
        }

        public void Commit()
        {
            CommitCalled = true;
            _events.Add("commit");
            if (ThrowOnCommit)
            {
                throw new IOException("Injected commit failure.");
            }
        }

        public void Dispose() => _events.Add("dispose");
    }

    private sealed class RecordingEnvironment
        : IProtectedPreparationEnvironment
    {
        public bool Elevated { get; set; } = true;
        public bool IsElevated() => Elevated;
        public string? GetCurrentExecutablePath() =>
            @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel\WireguardSplitTunnel.App.exe";
    }

    private sealed class RecordingInstalledReleaseLocator
        : IInstalledReleaseLocationProvider
    {
        public int CallCount { get; private set; }
        public InstalledReleaseLocation Location { get; set; } =
            InstalledReleaseLocation.Available(
                @"C:\Program Files\WireguardSplitTunnel",
                @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel\WireguardSplitTunnel.App.exe",
                @"C:\Program Files\WireguardSplitTunnel\WireguardSplitTunnel.Updater\WireguardSplitTunnel.Updater.exe",
                new SemanticVersion(1, 0, 0),
                currentManagedBytes: 4096);

        public InstalledReleaseLocation Locate(
            string? runningExecutablePath)
        {
            CallCount++;
            return Location;
        }
    }

    private sealed class RecordingArtifactBuilder
        : IProtectedPreparationArtifactBuilder
    {
        public int CallCount { get; private set; }
        public Action? AfterBuild { get; set; }

        public Task<ProtectedTransactionWorkspaceResult> BuildAsync(
            ProtectedUpdateMutexContext authority,
            ProtectedTransactionPreparationRequest request,
            LocalUpdateLayout localLayout,
            ProtectedTransactionLayout protectedLayout,
            InstalledReleaseLocation installedRelease,
            CancellationToken cancellationToken)
        {
            CallCount++;
            var result = Task.FromResult(
                ProtectedTransactionWorkspaceResult.Failed(
                    ProtectedTransactionPreparationError
                        .VerificationFailed,
                    "injected"));
            AfterBuild?.Invoke();
            return result;
        }
    }

    private sealed class NeverReparseInspector
        : IPathSafetyInspector
    {
        public bool IsReparsePoint(string path) => false;
    }

    private sealed class StreamOnlyProductVersionReader(
        string? version)
        : IExecutableProductVersionReader
    {
        public int PathCalls { get; private set; }
        public int StreamCalls { get; private set; }

        public string? ReadProductVersion(
            string executablePath)
        {
            PathCalls++;
            throw new InvalidOperationException(
                "The path overload must not be used.");
        }

        public string? ReadProductVersion(
            Stream executableStream)
        {
            StreamCalls++;
            return version;
        }
    }

    private static ProtectedStagedTransactionMaterial Material(
        ProtectedTransactionId transactionId)
    {
        var version = new SemanticVersion(2, 0, 0);
        return new ProtectedStagedTransactionMaterial(
            transactionId,
            version,
            PendingUpdateSource.Automatic,
            new ProtectedInstalledReleaseIdentity(
                @"C:\Program Files\WireguardSplitTunnel",
                VolumeSerialNumber: 1,
                RootFileIdLow: 2,
                RootFileIdHigh: 3,
                CurrentVersion: new SemanticVersion(1, 0, 0),
                MinimumAutoUpdateVersion: new SemanticVersion(1, 0, 0),
                RollbackCompatibleFromVersion:
                    new SemanticVersion(1, 0, 0),
                StateSchemaVersion: 1,
                ApplicationRelativePath:
                    UpdateReleaseContract.WindowsApplicationPath,
                UpdaterRelativePath:
                    UpdateReleaseContract.WindowsUpdaterPath,
                CurrentManifestSha256: Hash('c'),
                ManagedFiles:
                [
                    new ProtectedManagedFileIdentity(
                        UpdateReleaseContract.WindowsApplicationPath,
                        Length: 10,
                        Sha256: Hash('d'))
                ]),
            new ProtectedCandidateIdentity(
                Hash('a'),
                Hash('b'),
                ExpandedBytes: 20),
            HelperSha256: Hash('e'),
            new ProtectedJournalMetadata(
                ProtectedTransactionStore.JournalSchemaVersion,
                Generation: 0,
                Sha256: null));
    }

    private static string Hash(char value) =>
        new(value, 64);
}
