using FluentAssertions;
using WireguardSplitTunnel.Core.Updates;
using WireguardSplitTunnel.WindowsUpdate.GitHub;
using WireguardSplitTunnel.WindowsUpdate.Logging;
using WireguardSplitTunnel.WindowsUpdate.Staging;
using WireguardSplitTunnel.WindowsUpdate.Transactions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class WindowsUpdateCoordinatorTests
{
    private static readonly SemanticVersion CurrentVersion =
        new(1, 0, 0);
    private static readonly SemanticVersion CandidateVersion =
        new(2, 0, 0);
    private static readonly ProtectedTransactionId
        InspectedTransactionId =
        new(
            Guid.Parse(
                "10000000-0000-0000-0000-000000000001"));
    private static readonly ProtectedTransactionId
        RacedTransactionId =
        new(
            Guid.Parse(
                "20000000-0000-0000-0000-000000000002"));

    [Fact]
    public async Task AutomaticDue_PersistsTimestampBeforeNetworkAndUsesOneMonotonicDay()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Handler = cancellationToken =>
        {
            fixture.Trace.Add("network");
            return Task.FromResult(
                GitHubReleaseQueryResult.Failure(
                    GitHubReleaseQueryStatus.NetworkFailure,
                    "transport"));
        };

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await fixture.Release.WaitForCallsAsync(1);
        await fixture.Delay.WaitForRequestsAsync(1);

        fixture.Local.Saves.Should().ContainSingle();
        fixture.Local.Saves[0].LastAutomaticAttemptUtc
            .Should()
            .Be(fixture.Time.GetUtcNow());
        fixture.Trace.Should().ContainInOrder(
            "save",
            "network");
        fixture.Delay.Requested[0].Should().Be(
            UpdateSchedulePolicy.AutomaticInterval);

        fixture.Time.UtcNow =
            fixture.Time.UtcNow.AddYears(-10);
        fixture.Delay.Requested.Should().Equal(
            UpdateSchedulePolicy.AutomaticInterval);
    }

    [Fact]
    public async Task AutomaticNotDue_WaitsRemainingDelayThenRunsDespiteWallClockRollback()
    {
        var now = new DateTimeOffset(
            2026,
            7,
            30,
            0,
            0,
            0,
            TimeSpan.Zero);
        await using var fixture = CoordinatorFixture.Create(now);
        fixture.Local.Metadata = LocalUpdateMetadata.Empty with
        {
            LastAutomaticAttemptUtc = now.AddHours(-1)
        };

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await fixture.Delay.WaitForRequestsAsync(1);

        fixture.Delay.Requested[0].Should().Be(
            TimeSpan.FromHours(23));
        fixture.Release.CallCount.Should().Be(0);

        fixture.Time.UtcNow = now.AddYears(-1);
        fixture.Delay.CompleteNext();
        await fixture.Release.WaitForCallsAsync(1);

        fixture.Release.CallCount.Should().Be(1);
        fixture.Local.Metadata.LastAutomaticAttemptUtc
            .Should()
            .Be(fixture.Time.GetUtcNow());
    }

    [Fact]
    public async Task FutureTimestampBeyondTolerance_IsDueOnceAndReplaced()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = LocalUpdateMetadata.Empty with
        {
            LastAutomaticAttemptUtc =
                fixture.Time.GetUtcNow().AddMinutes(6)
        };

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await fixture.Release.WaitForCallsAsync(1);
        await fixture.Delay.WaitForRequestsAsync(1);

        fixture.Release.CallCount.Should().Be(1);
        fixture.Local.Metadata.LastAutomaticAttemptUtc
            .Should()
            .Be(fixture.Time.GetUtcNow());
        fixture.Delay.Requested.Should().Equal(
            UpdateSchedulePolicy.AutomaticInterval);
    }

    [Fact]
    public async Task CancelledAutomaticAttempt_DoesNotTightRetryWhenReenabled()
    {
        await using var fixture = CoordinatorFixture.Create();
        var entered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Release.Handler = async cancellationToken =>
        {
            entered.TrySetResult();
            await Task.Delay(
                Timeout.InfiniteTimeSpan,
                cancellationToken);
            throw new InvalidOperationException();
        };

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await fixture.Coordinator.SetAutomaticEnabledAsync(
            enabled: false,
            CancellationToken.None);
        await fixture.Coordinator.SetAutomaticEnabledAsync(
            enabled: true,
            CancellationToken.None);
        await fixture.Delay.WaitForRequestsAsync(1);

        fixture.Release.CallCount.Should().Be(1);
        fixture.Local.Metadata.LastAutomaticAttemptUtc
            .Should()
            .Be(fixture.Time.GetUtcNow());
        fixture.Delay.Requested[0].Should().Be(
            UpdateSchedulePolicy.AutomaticInterval);
    }

    [Fact]
    public async Task DisableThenEnableBeforeDrain_RestartsAutomaticScheduler()
    {
        await using var fixture = CoordinatorFixture.Create();
        var entered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var cancellationObserved = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var finishCancelledRequest = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Release.Handler = async cancellationToken =>
        {
            entered.TrySetResult();
            try
            {
                await Task.Delay(
                    Timeout.InfiniteTimeSpan,
                    cancellationToken);
            }
            catch (OperationCanceledException)
            {
                cancellationObserved.TrySetResult();
                await finishCancelledRequest.Task;
                throw;
            }

            return GitHubReleaseQueryResult.Failure(
                GitHubReleaseQueryStatus.NetworkFailure,
                "unexpected");
        };

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var disable =
            fixture.Coordinator.SetAutomaticEnabledAsync(
                enabled: false,
                CancellationToken.None);
        await cancellationObserved.Task.WaitAsync(
            TimeSpan.FromSeconds(5));

        await fixture.Coordinator.SetAutomaticEnabledAsync(
            enabled: true,
            CancellationToken.None);
        finishCancelledRequest.TrySetResult();
        await disable.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.Delay.WaitForRequestsAsync(1);

        fixture.Delay.Requested.Should().ContainSingle()
            .Which.Should()
            .Be(UpdateSchedulePolicy.AutomaticInterval);
    }

    [Fact]
    public async Task CancelledDisable_PersistsCleanupPendingBeforeDrain()
    {
        await using var fixture = CoordinatorFixture.Create();
        var entered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var cancellationObserved = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var finishCancelledRequest = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Release.Handler = async cancellationToken =>
        {
            entered.TrySetResult();
            try
            {
                await Task.Delay(
                    Timeout.InfiniteTimeSpan,
                    cancellationToken);
            }
            catch (OperationCanceledException)
            {
                cancellationObserved.TrySetResult();
                await finishCancelledRequest.Task;
                throw;
            }

            return GitHubReleaseQueryResult.Failure(
                GitHubReleaseQueryStatus.NetworkFailure,
                "unexpected");
        };

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        using var cancellation = new CancellationTokenSource();
        var disable =
            fixture.Coordinator.SetAutomaticEnabledAsync(
                enabled: false,
                cancellation.Token);
        await cancellationObserved.Task.WaitAsync(
            TimeSpan.FromSeconds(5));
        cancellation.Cancel();

        await FluentActions.Awaiting(() => disable)
            .Should()
            .ThrowAsync<OperationCanceledException>();
        finishCancelledRequest.TrySetResult();

        fixture.Local.Metadata.ProtectedRemovalPending
            .Should()
            .BeTrue();
    }

    [Fact]
    public async Task ManualCheck_BypassesDueTimeWithoutChangingAutomaticTimestamp()
    {
        await using var fixture = CoordinatorFixture.Create();
        var timestamp = fixture.Time.GetUtcNow();
        fixture.Local.Metadata = LocalUpdateMetadata.Empty with
        {
            LastAutomaticAttemptUtc = timestamp
        };
        await fixture.Coordinator.StartAsync(
            automaticEnabled: false,
            CancellationToken.None);
        fixture.Local.Saves.Clear();

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Release.CallCount.Should().Be(1);
        fixture.Local.Metadata.LastAutomaticAttemptUtc
            .Should()
            .Be(timestamp);
        fixture.Local.Saves.Should().BeEmpty();
    }

    [Fact]
    public async Task AutomaticAndManualChecks_ShareOneSemaphore()
    {
        await using var fixture = CoordinatorFixture.Create();
        var releaseFirst = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Release.Handler = async cancellationToken =>
        {
            if (fixture.Release.CallCount == 1)
            {
                await releaseFirst.Task.WaitAsync(
                    cancellationToken);
            }

            return GitHubReleaseQueryResult.Failure(
                GitHubReleaseQueryStatus.NetworkFailure,
                "transport");
        };

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await fixture.Release.WaitForCallsAsync(1);
        var manual = fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);
        await Task.Delay(50);

        fixture.Release.CallCount.Should().Be(1);
        releaseFirst.TrySetResult();
        await manual.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Release.CallCount.Should().Be(2);
        fixture.Release.MaximumConcurrency.Should().Be(1);
    }

    [Fact]
    public async Task SuccessfulCheck_PersistsValidatedCandidateBeforeProtectedPreparation()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Downloader.ArchiveCalls.Should().Be(1);
        fixture.Downloader.ChecksumCalls.Should().Be(1);
        fixture.Validator.CallCount.Should().Be(1);
        fixture.Local.Metadata.StagedUpdate.Should().NotBeNull();
        fixture.Local.Metadata.StagedUpdate!.Source
            .Should()
            .Be(PendingUpdateSource.Manual);
        fixture.Preparer.CallCount.Should().Be(1);
        fixture.Trace.IndexOf("save")
            .Should()
            .BeLessThan(fixture.Trace.IndexOf("prepare"));
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.ReadyForClose);
    }

    [Fact]
    public async Task CurrentReleaseApiDigestMismatch_NeverStagesOrPreparesThePackage()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease(Hash("other-archive"));

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Downloader.ArchiveCalls.Should().Be(1);
        fixture.Downloader.ChecksumCalls.Should().Be(1);
        fixture.Validator.CallCount.Should().Be(1);
        fixture.Local.Metadata.StagedUpdate.Should().BeNull();
        fixture.Preparer.CallCount.Should().Be(0);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.VerificationFailed);
        fixture.Statuses.Last().DetailCode.Should().Be(
            "release_digest");
    }

    [Fact]
    public async Task AutomaticLocalStaged_RestartElevatedBeforeDue_RemainsInertUntilOnlineRecheck()
    {
        await using var first = CoordinatorFixture.Create();
        first.Release.Result = SuccessfulRelease();
        first.Preparer.IsElevated = false;

        await first.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await first.Delay.WaitForRequestsAsync(1);

        first.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.ReadyNeedsElevation);
        first.Local.Metadata.StagedUpdate.Should().NotBeNull();
        first.Release.CallCount.Should().Be(1);
        await first.Coordinator.StopForCloseAsync(
            CancellationToken.None);

        first.Preparer.IsElevated = true;
        first.Release.Result = GitHubReleaseQueryResult.Failure(
            GitHubReleaseQueryStatus.NetworkFailure,
            "offline");
        await using var restarted = first.Restart();

        await restarted.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await restarted.Delay.WaitForRequestsAsync(2);

        restarted.Release.CallCount.Should().Be(1);
        restarted.Downloader.ArchiveCalls.Should().Be(1);
        restarted.Validator.CallCount.Should().Be(2);
        restarted.Local.ResolvedStages.Should().ContainSingle()
            .Which.Source.Should().Be(
                PendingUpdateSource.Automatic);
        restarted.Local.CandidateCleanupVersions.Should().Equal(
            CandidateVersion);
        restarted.Preparer.CallCount.Should().Be(0);
        restarted.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CheckFailed);
        restarted.Statuses.Last().DetailCode.Should().Be(
            "online_authentication_required");
    }

    [Fact]
    public async Task PersistedForgedLocalStage_FailsClosedOfflineBeforeValidation()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Automatic) with
        {
            LastAutomaticAttemptUtc = fixture.Time.GetUtcNow()
        };
        fixture.Local.ResolveResult =
            LocalUpdatePathResult.Failed(
                LocalUpdatePathError.MetadataMismatch);
        fixture.Release.Result = GitHubReleaseQueryResult.Failure(
            GitHubReleaseQueryStatus.NetworkFailure,
            "offline");

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await fixture.Delay.WaitForRequestsAsync(1);

        fixture.Release.CallCount.Should().Be(0);
        fixture.Validator.CallCount.Should().Be(0);
        fixture.Preparer.CallCount.Should().Be(0);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.VerificationFailed);
    }

    [Fact]
    public async Task ManualLocalStaged_RemainsInertWhileAutomaticChecksAreDisabled()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Manual);

        await fixture.Coordinator.StartAsync(
            automaticEnabled: false,
            CancellationToken.None);

        fixture.Release.CallCount.Should().Be(0);
        fixture.Validator.CallCount.Should().Be(1);
        fixture.Preparer.CallCount.Should().Be(0);
        fixture.Local.ResolvedStages.Should().ContainSingle()
            .Which.Source.Should().Be(PendingUpdateSource.Manual);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CheckFailed);
        fixture.Statuses.Last().DetailCode.Should().Be(
            "online_authentication_required");
    }

    [Fact]
    public async Task NonElevatedLocalStage_IsNotPresentedAsReadyWithoutAnOnlineRecheck()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Preparer.IsElevated = false;
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Manual);

        await fixture.Coordinator.StartAsync(
            automaticEnabled: false,
            CancellationToken.None);

        fixture.Validator.CallCount.Should().Be(0);
        fixture.Preparer.CallCount.Should().Be(0);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CheckFailed);
        fixture.Statuses.Last().DetailCode.Should().Be(
            "online_authentication_required");
    }

    [Fact]
    public async Task AutomaticRefreshOfManualVersion_UsesCurrentInvocationProvenance()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Manual);
        fixture.Release.Result = SuccessfulRelease();

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await fixture.Delay.WaitForRequestsAsync(1);
        await fixture.Coordinator.SetAutomaticEnabledAsync(
            enabled: false,
            CancellationToken.None);

        fixture.Local.Metadata.StagedUpdate.Should().BeNull();
        fixture.Local.CandidateCleanupVersions.Should().Equal(
            CandidateVersion,
            CandidateVersion);
        fixture.Local.CleanupVersions.Should().Equal(
            CandidateVersion);
    }

    [Fact]
    public async Task ManualRecheckOfExactCommittedStage_ReusesItWithoutOrphaningMetadata()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Automatic);
        fixture.Release.Result = SuccessfulRelease();
        fixture.Downloader.ChecksumResults.Enqueue(
            ReleaseAssetDownloadResult.Failure(
                ReleaseAssetDownloadStatus.FileFailure,
                "must_not_download"));

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Local.ResolvedStages.Should().ContainSingle();
        fixture.Local.CandidateCleanupVersions.Should().Equal(
            CandidateVersion);
        fixture.Local.CleanupVersions.Should().BeEmpty();
        fixture.Downloader.ArchiveCalls.Should().Be(0);
        fixture.Downloader.ChecksumCalls.Should().Be(0);
        fixture.Validator.CallCount.Should().Be(1);
        fixture.Local.Metadata.StagedUpdate
            .Should()
            .NotBeNull();
        fixture.Local.Metadata.StagedUpdate!.Source
            .Should()
            .Be(PendingUpdateSource.Manual);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.ReadyForClose);
    }

    [Fact]
    public async Task ExactCommittedStage_LiveApiSizeMismatchNeverPromotes()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Automatic);
        fixture.Release.Result = SuccessfulRelease();
        fixture.Validator.Handler = (
            _,
            layout,
            _) => Task.FromResult(
                UpdatePackageValidationResult.Valid(
                    FakePackage(layout) with
                    {
                        ArchiveBytes = 99
                    }));

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Preparer.CallCount.Should().Be(0);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.VerificationFailed);
        fixture.Statuses.Last().DetailCode.Should().Be(
            "release_digest");
    }

    [Fact]
    public async Task ExactCommittedStage_SaveFailurePreservesArtifactsAndOriginalMetadata()
    {
        await using var fixture = CoordinatorFixture.Create();
        var original = MetadataWithStage(
            PendingUpdateSource.Automatic);
        fixture.Local.Metadata = original;
        fixture.Local.SaveResults.Enqueue(
            LocalUpdateMetadataStoreResult.Failed(
                LocalUpdateMetadataStoreError.IoFailure));
        fixture.Release.Result = SuccessfulRelease();

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Local.Metadata.Should().BeSameAs(original);
        fixture.Local.CleanupVersions.Should().BeEmpty();
        fixture.Downloader.ArchiveCalls.Should().Be(0);
        fixture.Downloader.ChecksumCalls.Should().Be(0);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CheckFailed);
    }

    [Fact]
    public async Task AutomaticRecheckOfExactCommittedStage_ReusesItWithoutOrphaningMetadata()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Preparer.IsElevated = false;
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Manual);
        fixture.Release.Result = SuccessfulRelease();
        fixture.Downloader.ChecksumResults.Enqueue(
            ReleaseAssetDownloadResult.Failure(
                ReleaseAssetDownloadStatus.FileFailure,
                "must_not_download"));

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await fixture.Release.WaitForCallsAsync(1);
        await fixture.Delay.WaitForRequestsAsync(1);

        fixture.Local.ResolvedStages.Should().ContainSingle();
        fixture.Local.CandidateCleanupVersions.Should().Equal(
            CandidateVersion);
        fixture.Local.CleanupVersions.Should().BeEmpty();
        fixture.Downloader.ArchiveCalls.Should().Be(0);
        fixture.Downloader.ChecksumCalls.Should().Be(0);
        fixture.Validator.CallCount.Should().Be(1);
        fixture.Local.Metadata.StagedUpdate
            .Should()
            .NotBeNull();
        fixture.Local.Metadata.StagedUpdate!.Source
            .Should()
            .Be(PendingUpdateSource.Automatic);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.ReadyNeedsElevation);
    }

    [Fact]
    public async Task InvalidExactCommittedStage_ClearsMetadataBeforeCleanupAndFreshDownload()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Automatic);
        fixture.Local.ResolveResult =
            LocalUpdatePathResult.Failed(
                LocalUpdatePathError.MetadataMismatch);
        fixture.Release.Result = SuccessfulRelease();

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Local.Saves.Should().HaveCount(2);
        fixture.Local.Saves[0].StagedUpdate.Should().BeNull();
        fixture.Trace.IndexOf("save")
            .Should()
            .BeLessThan(
                fixture.Trace.IndexOf("cleanup_version"));
        fixture.Local.CleanupVersions.Should().Equal(
            CandidateVersion);
        fixture.Downloader.ArchiveCalls.Should().Be(1);
        fixture.Downloader.ChecksumCalls.Should().Be(1);
        fixture.Local.Metadata.StagedUpdate
            .Should()
            .NotBeNull();
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.ReadyForClose);
    }

    [Fact]
    public async Task InvalidExactCommittedStage_SaveFailurePreservesArtifactsAndMetadata()
    {
        await using var fixture = CoordinatorFixture.Create();
        var original = MetadataWithStage(
            PendingUpdateSource.Automatic);
        fixture.Local.Metadata = original;
        fixture.Local.ResolveResult =
            LocalUpdatePathResult.Failed(
                LocalUpdatePathError.MetadataMismatch);
        fixture.Local.SaveResults.Enqueue(
            LocalUpdateMetadataStoreResult.Failed(
                LocalUpdateMetadataStoreError.IoFailure));
        fixture.Release.Result = SuccessfulRelease();

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Local.Metadata.Should().BeSameAs(original);
        fixture.Local.CleanupVersions.Should().BeEmpty();
        fixture.Downloader.ArchiveCalls.Should().Be(0);
        fixture.Downloader.ChecksumCalls.Should().Be(0);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CheckFailed);
    }

    [Fact]
    public async Task NewlyDownloadedStage_SaveFailureNeverDeletesArtifactsBecauseCommitMayBeUnknown()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.SaveResults.Enqueue(
            LocalUpdateMetadataStoreResult.Failed(
                LocalUpdateMetadataStoreError.IoFailure));
        fixture.Release.Result = SuccessfulRelease();

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Downloader.ArchiveCalls.Should().Be(1);
        fixture.Downloader.ChecksumCalls.Should().Be(1);
        fixture.Local.CleanupVersions.Should().Equal(
            CandidateVersion);
        fixture.Preparer.CallCount.Should().Be(0);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CheckFailed);
        fixture.Statuses.Last().DetailCode.Should().Be(
            "staged_persistence");
    }

    [Fact]
    public async Task CancelledManualValidationOfExactStagePreservesMetadataAndArtifacts()
    {
        await using var fixture = CoordinatorFixture.Create();
        var original = MetadataWithStage(
            PendingUpdateSource.Automatic);
        fixture.Local.Metadata = original;
        fixture.Release.Result = SuccessfulRelease();
        var entered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Validator.Handler = async (
            _,
            _,
            cancellationToken) =>
        {
            entered.TrySetResult();
            try
            {
                await Task.Delay(
                    Timeout.InfiniteTimeSpan,
                    cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return UpdatePackageValidationResult.Failure(
                    UpdatePackageValidationError.Cancelled);
            }

            throw new InvalidOperationException();
        };
        using var cancellation = new CancellationTokenSource();

        var check = fixture.Coordinator.CheckNowAsync(
            cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await check.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Local.Metadata.Should().BeSameAs(original);
        fixture.Local.CleanupVersions.Should().BeEmpty();
        fixture.Downloader.ArchiveCalls.Should().Be(0);
        fixture.Downloader.ChecksumCalls.Should().Be(0);
        fixture.Preparer.CallCount.Should().Be(0);
    }

    [Fact]
    public async Task CancelledProtectedPreparationDoesNotPublishVerificationFailure()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        var entered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Preparer.Handler = async (
            _,
            _,
            _,
            _,
            _,
            cancellationToken) =>
        {
            entered.TrySetResult();
            try
            {
                await Task.Delay(
                    Timeout.InfiniteTimeSpan,
                    cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return ProtectedTransactionPreparationResult
                    .Failed(
                        ProtectedTransactionPreparationError
                            .Cancelled);
            }

            throw new InvalidOperationException();
        };
        using var cancellation = new CancellationTokenSource();

        var check = fixture.Coordinator.CheckNowAsync(
            cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await check.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Statuses.Should().NotContain(
            status => status.Kind
                == WindowsUpdateStatusKind.VerificationFailed);
        fixture.Logger.Entries.Should().Contain("check_cancelled");
        fixture.Local.Metadata.StagedUpdate.Should().NotBeNull();
        fixture.Local.CleanupVersions.Should().ContainSingle()
            .Which.Should().Be(CandidateVersion);
    }

    [Fact]
    public async Task CancellationAfterSuccessfulProtectedPreparationStillPublishesReadyForClose()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        using var cancellation = new CancellationTokenSource();
        fixture.Preparer.Handler = (
            _,
            _,
            _,
            _,
            _,
            _) =>
        {
            cancellation.Cancel();
            return Task.FromResult(
                ProtectedTransactionPreparationResult
                    .Completed(
                        new ProtectedTransactionId(
                            Guid.Parse(
                                "00112233-4455-6677-8899-aabbccddeeff"))));
        };

        await fixture.Coordinator.CheckNowAsync(
            cancellation.Token);

        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.ReadyForClose);
        fixture.Logger.Entries.Should().Contain(
            entry => entry.StartsWith(
                "update_ready ",
                StringComparison.Ordinal));
    }

    [Fact]
    public async Task AutomaticDisableDuringSuccessfulProtectedCommitNeverPublishesFalseReadyAndCleansCommittedStage()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        fixture.Authorization.CleanupResult =
            WindowsUpdateProtectedCleanupResult.Removed();
        var entered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseCommit = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Preparer.Handler = async (
            _,
            _,
            _,
            _,
            _,
            _) =>
        {
            entered.TrySetResult();
            await releaseCommit.Task;
            fixture.Authorization.State =
                WindowsUpdateProtectedState.Found(
                    InspectedTransactionId,
                    CandidateVersion,
                    PendingUpdateSource.Automatic,
                    ProtectedUpdatePhase.ProtectedStaged);
            return ProtectedTransactionPreparationResult
                .Completed(InspectedTransactionId);
        };

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var disable = fixture.Coordinator
            .SetAutomaticEnabledAsync(
                enabled: false,
                CancellationToken.None);
        var statusesBeforeCommit = fixture.Statuses.Count;

        releaseCommit.TrySetResult();
        await disable.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Statuses.Skip(statusesBeforeCommit)
            .Should().NotContain(
                status => status.Kind
                    == WindowsUpdateStatusKind.ReadyForClose);
        fixture.Authorization.CleanupCalls.Should().Be(1);
        fixture.Local.Metadata.ProtectedRemovalPending
            .Should().BeFalse();
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.Disabled);
    }

    [Fact]
    public async Task StartCancellationAfterResumeResultDoesNotConsumeTypedStatus()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Preparer.IsElevated = false;
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Manual);
        using var cancellation = new CancellationTokenSource();
        fixture.Coordinator.StatusChanged += (_, status) =>
        {
            if (status.DetailCode
                == "online_authentication_required")
            {
                cancellation.Cancel();
            }
        };

        await FluentActions.Awaiting(
                () => fixture.Coordinator.StartAsync(
                    automaticEnabled: false,
                    cancellation.Token))
            .Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task CancellationReturnedAsReleaseFailureDoesNotPublishCheckFailure()
    {
        await using var fixture = CoordinatorFixture.Create();
        var entered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Release.Handler = async cancellationToken =>
        {
            entered.TrySetResult();
            try
            {
                await Task.Delay(
                    Timeout.InfiniteTimeSpan,
                    cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return GitHubReleaseQueryResult.Failure(
                    GitHubReleaseQueryStatus.NetworkFailure,
                    "transport");
            }

            throw new InvalidOperationException();
        };
        using var cancellation = new CancellationTokenSource();

        var check = fixture.Coordinator.CheckNowAsync(
            cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await check.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Statuses.Should().NotContain(
            status => status.Kind
                == WindowsUpdateStatusKind.CheckFailed);
        fixture.Logger.Entries.Should().Contain("check_cancelled");
    }

    [Fact]
    public async Task CancellationReturnedAsInspectFailureDoesNotPublishCheckFailure()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        var entered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Authorization.InspectHandler =
            async cancellationToken =>
            {
                entered.TrySetResult();
                try
                {
                    await Task.Delay(
                        Timeout.InfiniteTimeSpan,
                        cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    return WindowsUpdateProtectedState.Failed(
                        "protected_inspect");
                }

                throw new InvalidOperationException();
            };
        using var cancellation = new CancellationTokenSource();

        var check = fixture.Coordinator.CheckNowAsync(
            cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await check.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Statuses.Should().NotContain(
            status => status.Kind
                == WindowsUpdateStatusKind.CheckFailed);
        fixture.Logger.Entries.Should().Contain("check_cancelled");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationReturnedAsDownloadFailureDoesNotPublishCheckFailure(
        bool checksum)
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        var entered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        Func<CancellationToken, Task<ReleaseAssetDownloadResult>>
            handler = async cancellationToken =>
            {
                entered.TrySetResult();
                try
                {
                    await Task.Delay(
                        Timeout.InfiniteTimeSpan,
                        cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    return ReleaseAssetDownloadResult.Failure(
                        ReleaseAssetDownloadStatus.FileFailure,
                        "file_io");
                }

                throw new InvalidOperationException();
            };
        if (checksum)
        {
            fixture.Downloader.ChecksumHandler = handler;
        }
        else
        {
            fixture.Downloader.ArchiveHandler = handler;
        }
        using var cancellation = new CancellationTokenSource();

        var check = fixture.Coordinator.CheckNowAsync(
            cancellation.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await check.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Statuses.Should().NotContain(
            status => status.Kind
                == WindowsUpdateStatusKind.CheckFailed);
        fixture.Logger.Entries.Should().Contain("check_cancelled");
    }

    [Fact]
    public async Task Disable_RemovesOnlyAutomaticLocalAndProtectedStaged()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Automatic);
        fixture.Authorization.CleanupResult =
            WindowsUpdateProtectedCleanupResult.Removed();
        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);

        await fixture.Coordinator.SetAutomaticEnabledAsync(
            enabled: false,
            CancellationToken.None);

        fixture.Local.CleanupVersions.Should().Equal(
            CandidateVersion);
        fixture.Local.Metadata.StagedUpdate.Should().BeNull();
        fixture.Local.Metadata.ProtectedRemovalPending
            .Should()
            .BeFalse();
        fixture.Authorization.CleanupCalls.Should().Be(1);
    }

    [Fact]
    public async Task StartupDisabled_ReconcilesAutomaticStateWithoutPendingMarker()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Automatic);
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                CandidateVersion,
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.ProtectedStaged);
        fixture.Authorization.CleanupResult =
            WindowsUpdateProtectedCleanupResult.Removed();

        await fixture.Coordinator.StartAsync(
            automaticEnabled: false,
            CancellationToken.None);

        fixture.Local.CleanupVersions.Should().Equal(
            CandidateVersion);
        fixture.Local.Metadata.StagedUpdate.Should().BeNull();
        fixture.Local.Metadata.ProtectedRemovalPending
            .Should()
            .BeFalse();
        fixture.Authorization.CleanupCalls.Should().Be(1);
        fixture.Release.CallCount.Should().Be(0);
        fixture.Validator.CallCount.Should().Be(0);
        fixture.Preparer.CallCount.Should().Be(0);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.Disabled);
    }

    [Fact]
    public async Task StartupEnabledPendingRemoval_ReconcilesThenReportsIdleWithoutEarlyCheck()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = LocalUpdateMetadata.Empty with
        {
            LastAutomaticAttemptUtc = fixture.Time.GetUtcNow(),
            ProtectedRemovalPending = true
        };
        fixture.Authorization.CleanupResult =
            WindowsUpdateProtectedCleanupResult.Removed();

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await fixture.Delay.WaitForRequestsAsync(1);

        fixture.Authorization.CleanupCalls.Should().Be(1);
        fixture.Local.Metadata.ProtectedRemovalPending
            .Should()
            .BeFalse();
        fixture.Release.CallCount.Should().Be(0);
        fixture.Delay.Requested.Should().Equal(
            UpdateSchedulePolicy.AutomaticInterval);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.Idle);
    }

    [Fact]
    public async Task StartupDisabledNonElevated_MarksProtectedCleanupPendingAndFailsAuthorizationClosed()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Preparer.IsElevated = false;
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Automatic);
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                CandidateVersion,
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.ProtectedStaged);
        fixture.Authorization.CleanupResult =
            WindowsUpdateProtectedCleanupResult
                .PendingElevation();

        await fixture.Coordinator.StartAsync(
            automaticEnabled: false,
            CancellationToken.None);
        var authorization = await fixture.Coordinator
            .TryAuthorizeAndLaunchAsync(
                ValidCloseContext(),
                CancellationToken.None);

        fixture.Local.Metadata.StagedUpdate.Should().BeNull();
        fixture.Local.Metadata.ProtectedRemovalPending
            .Should()
            .BeTrue();
        fixture.Authorization.CleanupCalls.Should().Be(1);
        fixture.Authorization.LastAutomaticAllowed
            .Should()
            .BeFalse();
        authorization.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome
                .NoProtectedTransaction);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CleanupPending);
    }

    [Fact]
    public async Task NonElevatedDisable_RecordsProtectedRemovalPending()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Preparer.IsElevated = false;
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Automatic);
        fixture.Authorization.CleanupResult =
            WindowsUpdateProtectedCleanupResult
                .PendingElevation();

        await fixture.Coordinator.SetAutomaticEnabledAsync(
            enabled: false,
            CancellationToken.None);

        fixture.Local.Metadata.StagedUpdate.Should().BeNull();
        fixture.Local.Metadata.ProtectedRemovalPending
            .Should()
            .BeTrue();
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CleanupPending);
    }

    [Fact]
    public async Task DisableCleanupFailure_RemainsFailClosedForAutomaticAuthorization()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Automatic);
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                CandidateVersion,
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.ProtectedStaged);
        fixture.Authorization.CleanupResult =
            WindowsUpdateProtectedCleanupResult.Failed("io");

        await fixture.Coordinator.SetAutomaticEnabledAsync(
            enabled: false,
            CancellationToken.None);
        var authorization =
            await fixture.Coordinator
                .TryAuthorizeAndLaunchAsync(
                    ValidCloseContext(),
                    CancellationToken.None);

        fixture.Local.Metadata.ProtectedRemovalPending
            .Should()
            .BeTrue();
        authorization.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome
                .NoProtectedTransaction);
        fixture.Authorization.LastAutomaticAllowed
            .Should()
            .BeFalse();
    }

    [Fact]
    public async Task Disable_PreservesManualStagingAndAuthorizedProtectedState()
    {
        await using var manual = CoordinatorFixture.Create();
        var manualStage = MetadataWithStage(
            PendingUpdateSource.Manual);
        manual.Local.Metadata = manualStage;

        await manual.Coordinator.SetAutomaticEnabledAsync(
            enabled: false,
            CancellationToken.None);

        manual.Local.Metadata.Should().Be(manualStage);
        manual.Local.CleanupVersions.Should().BeEmpty();

        await using var authorized = CoordinatorFixture.Create();
        authorized.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Automatic);
        authorized.Authorization.CleanupResult =
            WindowsUpdateProtectedCleanupResult
                .LaterPhasePreserved();

        await authorized.Coordinator.SetAutomaticEnabledAsync(
            enabled: false,
            CancellationToken.None);

        authorized.Authorization.CleanupCalls.Should().Be(1);
        authorized.Authorization.RevocationCalls
            .Should()
            .Be(0);
        authorized.Local.Metadata.ProtectedRemovalPending
            .Should()
            .BeFalse();
    }

    [Fact]
    public async Task DisableRacingWithOfflineResume_PreventsProtectedPreparation()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = MetadataWithStage(
            PendingUpdateSource.Automatic) with
        {
            LastAutomaticAttemptUtc = fixture.Time.GetUtcNow()
        };
        var validationEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var continueValidation = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Validator.Handler = async (
            candidateVersion,
            layout,
            cancellationToken) =>
        {
            validationEntered.TrySetResult();
            await continueValidation.Task.WaitAsync(
                cancellationToken);
            return UpdatePackageValidationResult.Valid(
                FakePackage(layout));
        };

        var startup = fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await validationEntered.Task.WaitAsync(
            TimeSpan.FromSeconds(5));
        var disable =
            fixture.Coordinator.SetAutomaticEnabledAsync(
                enabled: false,
                CancellationToken.None);

        continueValidation.TrySetResult();
        await Task.WhenAll(startup, disable)
            .WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Preparer.CallCount.Should().Be(0);
        fixture.Local.Metadata.StagedUpdate.Should().BeNull();
        fixture.Authorization.CleanupCalls.Should().Be(1);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.Disabled);
    }

    [Fact]
    public async Task DisableRacingWithClose_FailsAutomaticAuthorizationClosed()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = LocalUpdateMetadata.Empty with
        {
            LastAutomaticAttemptUtc = fixture.Time.GetUtcNow()
        };
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                CandidateVersion,
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.ProtectedStaged);
        fixture.Authorization.PauseBeforeAuthorization = true;
        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);

        var authorization =
            fixture.Coordinator.TryAuthorizeAndLaunchAsync(
                ValidCloseContext(),
                CancellationToken.None);
        await fixture.Authorization.AuthorizationEntered.Task
            .WaitAsync(TimeSpan.FromSeconds(5));
        var disable =
            fixture.Coordinator.SetAutomaticEnabledAsync(
                enabled: false,
                CancellationToken.None);

        fixture.Authorization.ContinueAuthorization
            .TrySetResult();
        var authorizationResult = await authorization
            .WaitAsync(TimeSpan.FromSeconds(5));
        await disable.WaitAsync(TimeSpan.FromSeconds(5));

        authorizationResult.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome
                .NoProtectedTransaction);
        fixture.Authorization.LastAutomaticAllowed
            .Should()
            .BeFalse();
    }

    [Fact]
    public async Task DisableAfterAuthorizationPredicate_WaitsForCommitAndPreservesCloseAuthorized()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Local.Metadata = LocalUpdateMetadata.Empty with
        {
            LastAutomaticAttemptUtc = fixture.Time.GetUtcNow()
        };
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                CandidateVersion,
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.ProtectedStaged);
        fixture.Authorization.PauseAfterAuthorizationAllowed = true;
        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);

        var authorization =
            fixture.Coordinator.TryAuthorizeAndLaunchAsync(
                ValidCloseContext(),
                CancellationToken.None);
        await fixture.Authorization.AuthorizationCommitEntered.Task
            .WaitAsync(TimeSpan.FromSeconds(5));
        var disable =
            fixture.Coordinator.SetAutomaticEnabledAsync(
                enabled: false,
                CancellationToken.None);
        var cleanupPendingBeforeCommit =
            fixture.Local.Metadata.ProtectedRemovalPending;
        fixture.Authorization.ContinueAuthorizationCommit
            .TrySetResult();
        var authorizationResult = await authorization
            .WaitAsync(TimeSpan.FromSeconds(5));
        await disable.WaitAsync(TimeSpan.FromSeconds(5));

        cleanupPendingBeforeCommit.Should().BeFalse(
            "disable must not pass its authorization linearization point while commit is in progress");
        authorizationResult.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome.HelperReady);
        fixture.Authorization.LastAutomaticAllowedAtCommit
            .Should()
            .BeTrue();
        fixture.Authorization.State.Phase.Should().Be(
            ProtectedUpdatePhase.CloseAuthorized);
    }

    [Fact]
    public async Task ProtectedCloseAuthorizedTransaction_BlocksNewerReplacement()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                new SemanticVersion(1, 5, 0),
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.CloseAuthorized);

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Downloader.ArchiveCalls.Should().Be(0);
        fixture.Validator.CallCount.Should().Be(0);
        fixture.Preparer.CallCount.Should().Be(0);
        fixture.Authorization.RevocationCalls
            .Should()
            .Be(0);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CheckFailed);
        fixture.Statuses.Last().DetailCode.Should().Be(
            "protected_in_progress");
    }

    [Fact]
    public async Task NonElevatedProtectedStageIsNeverReportedReadyForClose()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Preparer.IsElevated = false;
        fixture.Release.Result = SuccessfulRelease();
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                CandidateVersion,
                PendingUpdateSource.Manual,
                ProtectedUpdatePhase.ProtectedStaged);

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.ReadyNeedsElevation);
    }

    [Fact]
    public async Task DisabledAutomaticProtectedStageIsReportedCleanupPending()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                new SemanticVersion(2, 1, 0),
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.ProtectedStaged);

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CleanupPending);
        fixture.Statuses.Last().DetailCode.Should().Be(
            "automatic_authorization_disabled");
    }

    [Fact]
    public async Task ManualCheck_ReplacesSameVersionAutomaticProtectedStageWithManualAuthority()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                CandidateVersion,
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.ProtectedStaged);
        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Preparer.CallCount.Should().Be(1);
        fixture.Preparer.LastTrustedSource.Should().Be(
            PendingUpdateSource.Manual);
        fixture.Preparer.LastExpectedActive.Should().Be(
            fixture.Authorization.State);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.ReadyForClose);
    }

    [Fact]
    public async Task OlderProtectedStaged_IsSupersededBeforePreparingNewerCandidate()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                new SemanticVersion(1, 5, 0),
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.ProtectedStaged);
        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Preparer.CallCount.Should().Be(1);
        fixture.Preparer.LastExpectedActive.Should().Be(
            fixture.Authorization.State);
        fixture.Trace.Should().Contain("prepare");
    }

    [Fact]
    public async Task SupersedeRaceToCloseAuthorized_PreservesOldAndNeverPreparesNew()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                new SemanticVersion(1, 5, 0),
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.ProtectedStaged);
        fixture.Preparer.Handler = (
            _,
            _,
            _,
            _,
            _,
            _) =>
        {
            fixture.Authorization.State =
                fixture.Authorization.State with
                {
                    Phase = ProtectedUpdatePhase.CloseAuthorized
                };
            return Task.FromResult(
                ProtectedTransactionPreparationResult.Failed(
                    ProtectedTransactionPreparationError
                        .ActivationFailed,
                    "conflict"));
        };

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Preparer.CallCount.Should().Be(1);
        fixture.Authorization.RevocationCalls
            .Should()
            .Be(0);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CheckFailed);
    }

    [Fact]
    public async Task ReplacementPreparationFailureDoesNotDestructivelySupersedeOldStage()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                new SemanticVersion(1, 5, 0),
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.ProtectedStaged);
        fixture.Preparer.Handler = (
            _,
            _,
            _,
            _,
            _,
            _) => Task.FromResult(
            ProtectedTransactionPreparationResult.Failed(
                ProtectedTransactionPreparationError
                    .VerificationFailed,
                "replacement_failed"));

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Preparer.CallCount.Should().Be(1);
        fixture.Preparer.LastExpectedActive.Should().Be(
            fixture.Authorization.State);
        fixture.Authorization.State.TransactionId.Should().Be(
            InspectedTransactionId);
    }

    [Fact]
    public async Task SupersedeRaceToSameEvidenceDifferentId_FailsClosed()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        fixture.Authorization.State =
            WindowsUpdateProtectedState.Found(
                InspectedTransactionId,
                new SemanticVersion(1, 5, 0),
                PendingUpdateSource.Automatic,
                ProtectedUpdatePhase.ProtectedStaged);
        fixture.Preparer.Handler = (
            _,
            _,
            _,
            _,
            _,
            _) =>
        {
            fixture.Authorization.State =
                fixture.Authorization.State with
                {
                    TransactionId = RacedTransactionId
                };
            return Task.FromResult(
                ProtectedTransactionPreparationResult.Failed(
                    ProtectedTransactionPreparationError
                        .ActivationFailed,
                    "conflict"));
        };

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Preparer.LastExpectedActive!.TransactionId
            .Should().Be(InspectedTransactionId);
        fixture.Preparer.CallCount.Should().Be(1);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.CheckFailed);
    }

    [Fact]
    public async Task Close_CancelsAndDrainsDownloadBeforeAuthorizationInspection()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        fixture.Downloader.BlockArchiveUntilCancelled = true;
        var manual = fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);
        await fixture.Downloader.ArchiveEntered.Task
            .WaitAsync(TimeSpan.FromSeconds(5));

        var stop = fixture.Coordinator.StopForCloseAsync(
            CancellationToken.None);
        var authorization =
            fixture.Coordinator.TryAuthorizeAndLaunchAsync(
                ValidCloseContext(),
                CancellationToken.None);

        await Task.WhenAll(stop, manual, authorization)
            .WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Downloader.ArchiveCancelled
            .Should()
            .BeTrue();
        fixture.Trace.IndexOf("download_cancelled")
            .Should()
            .BeLessThan(
                fixture.Trace.IndexOf("authorize"));
    }

    [Fact]
    public async Task CancelledAfterArchiveCommit_RetryCleansDerivedStageBeforeFreshDownload()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        fixture.Downloader.EnforceCreateNewSemantics = true;
        fixture.Downloader.BlockChecksumUntilCancelled = true;
        using var cancellation = new CancellationTokenSource();

        var interrupted = fixture.Coordinator.CheckNowAsync(
            cancellation.Token);
        await fixture.Downloader.ChecksumEntered.Task
            .WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await interrupted.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Downloader.BlockChecksumUntilCancelled = false;
        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Downloader.ChecksumCancelled.Should().BeTrue();
        fixture.Downloader.ArchiveCalls.Should().Be(2);
        fixture.Local.CleanupVersions.Should().Equal(
            CandidateVersion,
            CandidateVersion);
        fixture.Preparer.CallCount.Should().Be(1);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.ReadyForClose);
    }

    [Fact]
    public async Task ChecksumFailureAfterArchiveCommit_RetryCleansStageBeforeFreshDownload()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Release.Result = SuccessfulRelease();
        fixture.Downloader.EnforceCreateNewSemantics = true;
        fixture.Downloader.ChecksumResults.Enqueue(
            ReleaseAssetDownloadResult.Failure(
                ReleaseAssetDownloadStatus.FileFailure,
                "file_io"));

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);
        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Downloader.ArchiveCalls.Should().Be(2);
        fixture.Downloader.ChecksumCalls.Should().Be(2);
        fixture.Local.CleanupVersions.Should().Equal(
            CandidateVersion,
            CandidateVersion);
        fixture.Validator.CallCount.Should().Be(1);
        fixture.Preparer.CallCount.Should().Be(1);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind.ReadyForClose);
    }

    [Fact]
    public async Task DeveloperLayout_ReportsAvailabilityWithoutDownloadOrPreparation()
    {
        await using var fixture = CoordinatorFixture.Create(
            developerLayout: true);
        fixture.Release.Result = SuccessfulRelease();

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Release.CallCount.Should().Be(1);
        fixture.Downloader.ArchiveCalls.Should().Be(0);
        fixture.Validator.CallCount.Should().Be(0);
        fixture.Preparer.CallCount.Should().Be(0);
        fixture.Statuses.Last().Kind.Should().Be(
            WindowsUpdateStatusKind
                .AutomaticInstallationUnavailable);
    }

    [Fact]
    public async Task PostInstallSelfTest_SuppressesAllCheckAndPreparationMutation()
    {
        await using var fixture = CoordinatorFixture.Create(
            postInstallSelfTest: true);
        fixture.Release.Result = SuccessfulRelease();

        await fixture.Coordinator.StartAsync(
            automaticEnabled: true,
            CancellationToken.None);
        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);
        var authorization =
            await fixture.Coordinator
                .TryAuthorizeAndLaunchAsync(
                    ValidCloseContext(),
                    CancellationToken.None);

        fixture.Release.CallCount.Should().Be(0);
        fixture.Local.Saves.Should().BeEmpty();
        fixture.Downloader.ArchiveCalls.Should().Be(0);
        fixture.Validator.CallCount.Should().Be(0);
        fixture.Preparer.CallCount.Should().Be(0);
        fixture.Authorization.AuthorizationCalls
            .Should()
            .Be(0);
        authorization.Outcome.Should().Be(
            UpdateCloseAuthorizationOutcome
                .NoProtectedTransaction);
    }

    [Fact]
    public async Task FailureStatusAndLog_SanitizeUntrustedDetail()
    {
        await using var fixture = CoordinatorFixture.Create();
        const string secret =
            "Bearer token C:\\Users\\name\\staging "
            + "{\"state\":\"secret\",\"account\":\"x@y\"}";
        fixture.Release.Result = new GitHubReleaseQueryResult(
            GitHubReleaseQueryStatus.InvalidResponse,
            Release: null,
            secret);

        await fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);

        fixture.Statuses.Last().DetailCode.Should().Be(
            "invalid");
        fixture.Logger.Entries.Should().NotContain(
            entry => entry.Contains(
                "Bearer",
                StringComparison.Ordinal)
                || entry.Contains(
                    "C:\\Users",
                    StringComparison.Ordinal)
                || entry.Contains(
                    "state",
                    StringComparison.Ordinal)
                || entry.Contains(
                    "account",
                    StringComparison.Ordinal));
    }

    [Fact]
    public async Task FaultyLogger_CannotEscapeCheckOrAuthorizationPaths()
    {
        await using var fixture = CoordinatorFixture.Create();
        fixture.Logger.Throw = true;

        var check = () => fixture.Coordinator.CheckNowAsync(
            CancellationToken.None);
        var authorization = () =>
            fixture.Coordinator.TryAuthorizeAndLaunchAsync(
                ValidCloseContext(),
                CancellationToken.None);

        await check.Should().NotThrowAsync();
        await authorization.Should().NotThrowAsync();
    }

    private static LocalUpdateMetadata MetadataWithStage(
        PendingUpdateSource source)
    {
        var layout = FakeLayout(CandidateVersion);
        return LocalUpdateMetadata.Empty with
        {
            StagedUpdate = new LocalStagedUpdate(
                CandidateVersion,
                layout.ArchivePath,
                layout.ChecksumPath,
                layout.ManifestPath,
                layout.CandidateRoot,
                Hash("archive"),
                Hash("manifest"),
                source)
        };
    }

    private static GitHubReleaseQueryResult SuccessfulRelease(
        string? archiveSha256 = null)
    {
        var tag = "v" + CandidateVersion;
        var root =
            $"https://github.com/radmanyeung/"
            + $"wireguard-switch/releases/download/{tag}/";
        return GitHubReleaseQueryResult.Success(
            new GitHubReleaseMetadata(
                tag,
                draft: false,
                prerelease: false,
                [
                    new GitHubReleaseAsset(
                        UpdateReleaseContract.WindowsAssetName,
                        new Uri(
                            root
                            + UpdateReleaseContract
                                .WindowsAssetName),
                        100,
                        archiveSha256 ?? Hash("archive")),
                    new GitHubReleaseAsset(
                        UpdateReleaseContract
                            .WindowsChecksumAssetName,
                        new Uri(
                            root
                            + UpdateReleaseContract
                                .WindowsChecksumAssetName),
                        64,
                        Hash("checksum"))
                ]));
    }

    private static UpdateCloseAuthorizationContext
        ValidCloseContext() =>
        new(
            ApplicationCloseIntent.UserOrApplicationClose,
            IsElevated: true,
            IsPostInstallSelfTest: false,
            ProcessId: 42,
            CreationTimeFileTimeUtc: 100,
            ImagePath:
                "C:\\Program Files\\WireguardSplitTunnel"
                + "\\WireguardSplitTunnel.App.exe");

    private static LocalUpdateLayout FakeLayout(
        SemanticVersion version)
    {
        var root = Path.Combine(
            "C:\\Local",
            version.ToString());
        return new LocalUpdateLayout(
            version,
            "C:\\Local",
            "C:\\Local\\metadata.json",
            "C:\\Local\\updates",
            root,
            Path.Combine(root, "staging"),
            Path.Combine(root, "staging", "update.zip"),
            Path.Combine(root, "staging", "update.zip.sha256"),
            Path.Combine(root, "candidate"),
            Path.Combine(
                root,
                "candidate",
                UpdateReleaseContract.ReleaseManifestPath));
    }

    private static ValidatedUpdatePackage FakePackage(
        LocalUpdateLayout layout)
    {
        var manifest = new ReleaseManifest(
            schemaVersion: 1,
            version: layout.Version.ToString(),
            UpdateReleaseContract.WindowsRuntimeIdentifier,
            minimumAutoUpdateVersion: "1.0.0",
            rollbackCompatibleFromVersion: "1.0.0",
            stateSchemaVersion: 1,
            UpdateReleaseContract.WindowsApplicationPath,
            UpdateReleaseContract.WindowsUpdaterPath,
            UpdateReleaseContract.RequiredLauncherPaths,
            [
                new ReleasePayloadFile(
                    UpdateReleaseContract
                        .WindowsApplicationPath,
                    1,
                    Hash("app")),
                new ReleasePayloadFile(
                    UpdateReleaseContract
                        .WindowsUpdaterPath,
                    1,
                    Hash("updater"))
            ]);
        return new ValidatedUpdatePackage(
            layout.Version,
            layout.ArchivePath,
            layout.ManifestPath,
            Hash("archive"),
            Hash("manifest"),
            layout.CandidateRoot,
            ArchiveBytes: 100,
            ExpandedBytes: 200,
            RequiredDiskBytes: 300,
            manifest);
    }

    private static string Hash(string value) =>
        Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(value)))
            .ToLowerInvariant();

    private sealed class CoordinatorFixture : IAsyncDisposable
    {
        private CoordinatorFixture(
            ManualTimeProvider time,
            FakeReleaseClient release,
            FakeDownloader downloader,
            FakeValidator validator,
            FakeLocalStore local,
            FakePreparer preparer,
            FakeAuthorizationHelper authorization,
            FakeDelay delay,
            FakeLogger logger,
            List<string> trace,
            bool developerLayout,
            bool postInstallSelfTest)
        {
            Time = time;
            Release = release;
            Downloader = downloader;
            Validator = validator;
            Local = local;
            Preparer = preparer;
            Authorization = authorization;
            Delay = delay;
            Logger = logger;
            Trace = trace;
            Coordinator = new WindowsUpdateCoordinator(
                CurrentVersion,
                developerLayout,
                postInstallSelfTest,
                release,
                downloader,
                validator,
                local,
                preparer,
                authorization,
                time,
                delay,
                logger);
            Coordinator.StatusChanged += (_, status) =>
                Statuses.Add(status);
        }

        public WindowsUpdateCoordinator Coordinator { get; }
        public ManualTimeProvider Time { get; }
        public FakeReleaseClient Release { get; }
        public FakeDownloader Downloader { get; }
        public FakeValidator Validator { get; }
        public FakeLocalStore Local { get; }
        public FakePreparer Preparer { get; }
        public FakeAuthorizationHelper Authorization { get; }
        public FakeDelay Delay { get; }
        public FakeLogger Logger { get; }
        public List<string> Trace { get; }
        public List<WindowsUpdateStatus> Statuses { get; } = [];

        public static CoordinatorFixture Create(
            DateTimeOffset? now = null,
            bool developerLayout = false,
            bool postInstallSelfTest = false)
        {
            var trace = new List<string>();
            var time = new ManualTimeProvider(
                now
                ?? new DateTimeOffset(
                    2026,
                    7,
                    30,
                    0,
                    0,
                    0,
                    TimeSpan.Zero));
            var local = new FakeLocalStore(trace);
            var release = new FakeReleaseClient();
            var downloader = new FakeDownloader(trace);
            local.OnCleanupVersion = downloader.RemoveArtifacts;
            var validator = new FakeValidator();
            var preparer = new FakePreparer(trace);
            var authorization =
                new FakeAuthorizationHelper(trace);
            var delay = new FakeDelay();
            var logger = new FakeLogger();
            return new CoordinatorFixture(
                time,
                release,
                downloader,
                validator,
                local,
                preparer,
                authorization,
                delay,
                logger,
                trace,
                developerLayout,
                postInstallSelfTest);
        }

        public CoordinatorFixture Restart() =>
            new(
                Time,
                Release,
                Downloader,
                Validator,
                Local,
                Preparer,
                Authorization,
                Delay,
                Logger,
                Trace,
                developerLayout: false,
                postInstallSelfTest: false);

        public async ValueTask DisposeAsync()
        {
            using var deadline =
                new CancellationTokenSource(
                    TimeSpan.FromSeconds(5));
            await Coordinator.StopForCloseAsync(
                deadline.Token);
        }
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        public ManualTimeProvider(DateTimeOffset utcNow)
        {
            UtcNow = utcNow;
        }

        public DateTimeOffset UtcNow { get; set; }

        public override DateTimeOffset GetUtcNow() => UtcNow;
    }

    private sealed class FakeDelay : IWindowsUpdateDelay
    {
        private readonly object _gate = new();
        private readonly Queue<TaskCompletionSource> _pending = [];

        public List<TimeSpan> Requested { get; } = [];

        public Task DelayAsync(
            TimeSpan delay,
            CancellationToken cancellationToken)
        {
            var completion = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_gate)
            {
                Requested.Add(delay);
                _pending.Enqueue(completion);
            }

            cancellationToken.Register(
                static state =>
                    ((TaskCompletionSource)state!)
                        .TrySetCanceled(),
                completion);
            return completion.Task;
        }

        public void CompleteNext()
        {
            TaskCompletionSource completion;
            lock (_gate)
            {
                completion = _pending.Dequeue();
            }

            completion.TrySetResult();
        }

        public Task WaitForRequestsAsync(int count) =>
            WaitUntilAsync(() =>
            {
                lock (_gate)
                {
                    return Requested.Count >= count;
                }
            });
    }

    private sealed class FakeReleaseClient : IGitHubReleaseClient
    {
        private int _active;
        private int _callCount;

        public GitHubReleaseQueryResult Result { get; set; } =
            GitHubReleaseQueryResult.Failure(
                GitHubReleaseQueryStatus.NetworkFailure,
                "transport");

        public Func<
            CancellationToken,
            Task<GitHubReleaseQueryResult>>? Handler
        {
            get;
            set;
        }

        public int CallCount => Volatile.Read(ref _callCount);
        public int MaximumConcurrency { get; private set; }

        public async Task<GitHubReleaseQueryResult>
            GetLatestAsync(
                CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _callCount);
            var active = Interlocked.Increment(ref _active);
            MaximumConcurrency = Math.Max(
                MaximumConcurrency,
                active);
            try
            {
                return Handler is null
                    ? Result
                    : await Handler(cancellationToken);
            }
            finally
            {
                Interlocked.Decrement(ref _active);
            }
        }

        public Task WaitForCallsAsync(int count) =>
            WaitUntilAsync(() => CallCount >= count);
    }

    private sealed class FakeDownloader : IReleaseAssetDownloader
    {
        private readonly List<string> _trace;
        private readonly HashSet<SemanticVersion> _archives = [];

        public FakeDownloader(List<string> trace)
        {
            _trace = trace;
        }

        public int ArchiveCalls { get; private set; }
        public int ChecksumCalls { get; private set; }
        public bool BlockArchiveUntilCancelled { get; set; }
        public bool BlockChecksumUntilCancelled { get; set; }
        public bool EnforceCreateNewSemantics { get; set; }
        public bool ArchiveCancelled { get; private set; }
        public bool ChecksumCancelled { get; private set; }
        public Func<
            CancellationToken,
            Task<ReleaseAssetDownloadResult>>? ArchiveHandler
        {
            get;
            set;
        }
        public Func<
            CancellationToken,
            Task<ReleaseAssetDownloadResult>>? ChecksumHandler
        {
            get;
            set;
        }
        public Queue<ReleaseAssetDownloadResult>
            ChecksumResults
        { get; } = [];
        public TaskCompletionSource ArchiveEntered { get; } =
            new(
                TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ChecksumEntered { get; } =
            new(
                TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<ReleaseAssetDownloadResult>
            DownloadArchiveAsync(
                SelectedWindowsRelease release,
                LocalUpdateLayout layout,
                CancellationToken cancellationToken)
        {
            ArchiveCalls++;
            ArchiveEntered.TrySetResult();
            if (ArchiveHandler is not null)
            {
                return await ArchiveHandler(cancellationToken);
            }

            if (BlockArchiveUntilCancelled)
            {
                try
                {
                    await Task.Delay(
                        Timeout.InfiniteTimeSpan,
                        cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    ArchiveCancelled = true;
                    _trace.Add("download_cancelled");
                    throw;
                }
            }

            if (EnforceCreateNewSemantics
                && !_archives.Add(release.Version))
            {
                return ReleaseAssetDownloadResult.Failure(
                    ReleaseAssetDownloadStatus.DestinationExists,
                    "destination_exists");
            }

            return ReleaseAssetDownloadResult.Success();
        }

        public async Task<ReleaseAssetDownloadResult>
            DownloadChecksumAsync(
                SelectedWindowsRelease release,
                LocalUpdateLayout layout,
                CancellationToken cancellationToken)
        {
            ChecksumCalls++;
            ChecksumEntered.TrySetResult();
            if (ChecksumHandler is not null)
            {
                return await ChecksumHandler(cancellationToken);
            }

            if (BlockChecksumUntilCancelled)
            {
                try
                {
                    await Task.Delay(
                        Timeout.InfiniteTimeSpan,
                        cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    ChecksumCancelled = true;
                    throw;
                }
            }

            return ChecksumResults.Count > 0
                ? ChecksumResults.Dequeue()
                : ReleaseAssetDownloadResult.Success();
        }

        public void RemoveArtifacts(SemanticVersion version) =>
            _archives.Remove(version);
    }

    private sealed class FakeValidator
        : IWindowsUpdatePackageValidator
    {
        public int CallCount { get; private set; }
        public Func<
            SemanticVersion,
            LocalUpdateLayout,
            CancellationToken,
            Task<UpdatePackageValidationResult>>? Handler
        {
            get;
            set;
        }

        public Task<UpdatePackageValidationResult>
            ValidateAsync(
                SemanticVersion candidateVersion,
                LocalUpdateLayout layout,
                CancellationToken cancellationToken)
        {
            CallCount++;
            return Handler is null
                ? Task.FromResult(
                    UpdatePackageValidationResult.Valid(
                        FakePackage(layout)))
                : Handler(
                    candidateVersion,
                    layout,
                    cancellationToken);
        }
    }

    private sealed class FakeLocalStore
        : IWindowsUpdateLocalStore
    {
        private readonly List<string> _trace;

        public FakeLocalStore(List<string> trace)
        {
            _trace = trace;
        }

        public LocalUpdateMetadata Metadata { get; set; } =
            LocalUpdateMetadata.Empty;
        public LocalUpdatePathResult? ResolveResult { get; set; }
        public List<LocalUpdateMetadata> Saves { get; } = [];
        public Queue<LocalUpdateMetadataStoreResult> SaveResults
        { get; } = [];
        public List<LocalStagedUpdate> ResolvedStages { get; } = [];
        public List<SemanticVersion> CandidateCleanupVersions { get; } = [];
        public List<SemanticVersion> CleanupVersions { get; } = [];
        public Action<SemanticVersion>? OnCleanupVersion
        {
            get;
            set;
        }

        public LocalUpdateMetadata Load() => Metadata;

        public LocalUpdateMetadataStoreResult Save(
            LocalUpdateMetadata metadata)
        {
            if (SaveResults.Count > 0)
            {
                _trace.Add("save_failed");
                return SaveResults.Dequeue();
            }

            Metadata = metadata;
            Saves.Add(metadata);
            _trace.Add("save");
            return LocalUpdateMetadataStoreResult.Saved();
        }

        public LocalUpdatePathResult EnsureStaging(
            SemanticVersion version) =>
            LocalUpdatePathResult.Valid(FakeLayout(version));

        public LocalUpdatePathResult TryResolve(
            LocalStagedUpdate stagedUpdate)
        {
            ResolvedStages.Add(stagedUpdate);
            return ResolveResult
                ?? LocalUpdatePathResult.Valid(
                    FakeLayout(stagedUpdate.Version));
        }

        public LocalUpdatePathResult CleanupCandidate(
            SemanticVersion version)
        {
            CandidateCleanupVersions.Add(version);
            return LocalUpdatePathResult.Valid(
                FakeLayout(version));
        }

        public LocalUpdatePathResult CleanupVersion(
            SemanticVersion version)
        {
            CleanupVersions.Add(version);
            _trace.Add("cleanup_version");
            OnCleanupVersion?.Invoke(version);
            return LocalUpdatePathResult.Valid(
                FakeLayout(version));
        }
    }

    private sealed class FakePreparer
        : IWindowsUpdateProtectedPreparer
    {
        private readonly List<string> _trace;

        public FakePreparer(List<string> trace)
        {
            _trace = trace;
        }

        public bool IsElevated { get; set; } = true;
        public int CallCount { get; private set; }
        public Func<
            SelectedWindowsRelease,
            ValidatedUpdatePackage,
            LocalStagedUpdate,
            PendingUpdateSource,
            WindowsUpdateProtectedState?,
            CancellationToken,
            Task<ProtectedTransactionPreparationResult>>? Handler
        {
            get;
            set;
        }
        public PendingUpdateSource? LastTrustedSource
        {
            get;
            private set;
        }
        public WindowsUpdateProtectedState? LastExpectedActive
        {
            get;
            private set;
        }

        public Task<ProtectedTransactionPreparationResult>
            PrepareAsync(
                SelectedWindowsRelease trustedRelease,
                ValidatedUpdatePackage package,
                LocalStagedUpdate stagedUpdate,
                PendingUpdateSource trustedSource,
                WindowsUpdateProtectedState? expectedActive,
                CancellationToken cancellationToken)
        {
            CallCount++;
            LastTrustedSource = trustedSource;
            LastExpectedActive = expectedActive;
            _trace.Add("prepare");
            return Handler is null
                ? Task.FromResult(
                ProtectedTransactionPreparationResult
                    .Completed(
                        new ProtectedTransactionId(
                            Guid.Parse(
                                "00112233-4455-6677-8899-aabbccddeeff"))))
                : Handler(
                    trustedRelease,
                    package,
                    stagedUpdate,
                    trustedSource,
                    expectedActive,
                    cancellationToken);
        }
    }

    private sealed class FakeAuthorizationHelper
        : IWindowsUpdateAuthorizationHelper
    {
        private readonly List<string> _trace;

        public FakeAuthorizationHelper(List<string> trace)
        {
            _trace = trace;
        }

        public WindowsUpdateProtectedState State { get; set; } =
            WindowsUpdateProtectedState.None();
        public WindowsUpdateProtectedCleanupResult CleanupResult
        {
            get;
            set;
        } = WindowsUpdateProtectedCleanupResult.NothingToDo();
        public int CleanupCalls { get; private set; }
        public int RevocationCalls { get; private set; }
        public int AuthorizationCalls { get; private set; }
        public bool PauseBeforeAuthorization { get; set; }
        public bool? LastAutomaticAllowed { get; private set; }
        public bool PauseAfterAuthorizationAllowed { get; set; }
        public bool? LastAutomaticAllowedAtCommit { get; private set; }
        public Func<
            CancellationToken,
            Task<WindowsUpdateProtectedState>>? InspectHandler
        {
            get;
            set;
        }
        public TaskCompletionSource AuthorizationEntered { get; } =
            new(
                TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ContinueAuthorization { get; } =
            new(
                TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource AuthorizationCommitEntered
        {
            get;
        } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ContinueAuthorizationCommit
        {
            get;
        } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<WindowsUpdateProtectedState> InspectAsync(
            CancellationToken cancellationToken) =>
            InspectHandler is null
                ? Task.FromResult(State)
                : InspectHandler(cancellationToken);

        public Task<WindowsUpdateProtectedCleanupResult>
            CleanupAutomaticProtectedStagedAsync(
                bool isElevated,
                CancellationToken cancellationToken)
        {
            CleanupCalls++;
            return Task.FromResult(CleanupResult);
        }

        public async Task<UpdateCloseAuthorizationResult>
            TryAuthorizeAndLaunchAsync(
                UpdateCloseAuthorizationContext context,
                Func<PendingUpdateSource, bool>
                    isAuthorizationAllowed,
                Func<PendingUpdateSource,
                    IWindowsUpdateAuthorizationCommitLease?>
                    tryAcquireAuthorizationCommitLease,
                CancellationToken cancellationToken)
        {
            AuthorizationCalls++;
            _trace.Add("authorize");
            AuthorizationEntered.TrySetResult();
            if (PauseBeforeAuthorization)
            {
                await ContinueAuthorization.Task.WaitAsync(
                    cancellationToken);
            }

            if (State is
                {
                    Exists: true,
                    Source: { } source,
                    Phase:
                        ProtectedUpdatePhase.ProtectedStaged
                })
            {
                var allowed =
                    isAuthorizationAllowed(source);
                if (source == PendingUpdateSource.Automatic)
                {
                    LastAutomaticAllowed = allowed;
                }

                using var commitLease = allowed
                    ? tryAcquireAuthorizationCommitLease(source)
                    : null;
                if (allowed && commitLease is null)
                {
                    allowed = false;
                }

                if (allowed && PauseAfterAuthorizationAllowed)
                {
                    AuthorizationCommitEntered.TrySetResult();
                    await ContinueAuthorizationCommit.Task
                        .WaitAsync(cancellationToken);
                    allowed = isAuthorizationAllowed(source);
                    if (source
                        == PendingUpdateSource.Automatic)
                    {
                        LastAutomaticAllowedAtCommit = allowed;
                    }
                }

                if (allowed)
                {
                    State = State with
                    {
                        Phase = ProtectedUpdatePhase
                            .CloseAuthorized
                    };
                    return UpdateCloseAuthorizationResult
                        .HelperReady();
                }
            }

            return UpdateCloseAuthorizationResult
                .NoProtectedTransaction();
        }
    }

    private sealed class FakeLogger : IUpdaterEventLogger
    {
        public List<string> Entries { get; } = [];
        public bool Throw { get; set; }

        public bool TryAppend(
            string eventCode,
            string? detailCode = null,
            string? version = null)
        {
            if (Throw)
            {
                throw new IOException("logger failed");
            }

            Entries.Add(
                string.Join(
                    " ",
                    new[]
                    {
                        eventCode,
                        detailCode,
                        version
                    }.Where(value => value is not null)));
            return true;
        }
    }

    private static async Task WaitUntilAsync(
        Func<bool> predicate)
    {
        using var deadline =
            new CancellationTokenSource(
                TimeSpan.FromSeconds(5));
        while (!predicate())
        {
            await Task.Delay(10, deadline.Token);
        }
    }
}
