using FluentAssertions;
using WireguardSplitTunnel.Core.Services;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class CloseDisconnectCoordinatorTests
{
    private static readonly WindowsTunnelServiceIdentity Sg = Target("SG");
    private static readonly WindowsTunnelServiceIdentity External = Target("external.tunnel-1");
    private static readonly WindowsTunnelServiceIdentity NewAfterCrash = Target("new-after-crash");

    [Fact]
    public async Task Disconnect_MultipleAndExternalTargets_RecordsOneBatchVerifiesAndCompletes()
    {
        var events = new List<string>();
        var journal = new FakeJournal(events);
        var enumerator = new FakeEnumerator(events)
            .Returns(External, Sg)
            .Returns();
        var stop = new FakeStop(events);
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var preparation = await coordinator.PrepareAsync(CancellationToken.None);
        var result = await coordinator.DisconnectAsync(preparation, CancellationToken.None);

        result.Success.Should().BeTrue();
        result.Failures.Should().BeEmpty();
        result.UnresolvedTargets.Should().BeEmpty();
        stop.Batches.Should().ContainSingle();
        stop.Batches[0].Select(target => target.ServiceName).Should().Equal(
            External.ServiceName,
            Sg.ServiceName);
        journal.SavedEntries.Should().ContainSingle();
        journal.SavedEntries[0].Phase.Should().Be(CloseDisconnectJournalPhase.TargetsRecorded);
        journal.SavedEntries[0].Targets.Select(target => target.ServiceName).Should().Equal(
            External.ServiceName,
            Sg.ServiceName);
        journal.Entry.Should().BeNull();
        events.Should().Equal("load", "load", "enumerate", "save", "stop", "enumerate", "complete", "load");
    }

    [Fact]
    public async Task Disconnect_NoTargets_SucceedsWithoutElevationOrJournalMutation()
    {
        var journal = new FakeJournal();
        var enumerator = new FakeEnumerator().Returns();
        var stop = new FakeStop();
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var preparation = await coordinator.PrepareAsync(CancellationToken.None);
        var result = await coordinator.DisconnectAsync(preparation, CancellationToken.None);

        result.Success.Should().BeTrue();
        stop.Batches.Should().BeEmpty();
        journal.SavedEntries.Should().BeEmpty();
        journal.CompleteCalls.Should().Be(0);
        enumerator.Calls.Should().Be(1);
    }

    [Fact]
    public async Task Disconnect_NoTargetsWithPreexistingEmptyJournal_CompletesWithoutSavingOrStopping()
    {
        var entry = Entry(targets: []);
        var journal = new FakeJournal { Entry = entry };
        var enumerator = new FakeEnumerator().Returns();
        var stop = new FakeStop();
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.DisconnectAsync(
            Prepared(entry.OperationId),
            CancellationToken.None);

        result.Success.Should().BeTrue();
        stop.Batches.Should().BeEmpty();
        journal.SavedEntries.Should().BeEmpty();
        journal.CompleteCalls.Should().Be(1);
        journal.Entry.Should().BeNull();
    }

    [Fact]
    public async Task Prepare_JournalLoadFailure_ReturnsSafeTypedFailureWithoutCapturingEnable()
    {
        var journal = new FakeJournal
        {
            Entry = Entry(),
            LoadException = SecretFailure("journal load")
        };
        var activitySource = new FakeActivitySource();
        var coordinator = CreateCoordinator(journal, activitySource: activitySource);

        var preparation = await coordinator.PrepareAsync(CancellationToken.None);
        var result = await coordinator.DisconnectAsync(preparation, CancellationToken.None);

        preparation.Failure.Should().NotBeNull();
        preparation.Failure!.Kind.Should().Be(CloseDisconnectFailureKind.Journal);
        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Journal);
        activitySource.CaptureCalls.Should().Be(0);
        journal.Entry.Should().NotBeNull();
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_JournalSaveFailure_PreventsStopAndPreservesJournal()
    {
        var original = Entry(targets: [Sg]);
        var journal = new FakeJournal
        {
            Entry = original,
            SaveException = SecretFailure("journal save")
        };
        var enumerator = new FakeEnumerator().Returns(Sg, External);
        var stop = new FakeStop();
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Journal);
        stop.Batches.Should().BeEmpty();
        journal.Entry.Should().BeSameAs(original);
        journal.CompleteCalls.Should().Be(0);
        enumerator.Calls.Should().Be(1);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_InitialEnumerationFailure_DoesNotStopOrCompleteJournal()
    {
        var original = Entry();
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator().Throws(SecretFailure("enumeration"));
        var stop = new FakeStop();
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Enumeration);
        stop.Batches.Should().BeEmpty();
        journal.Entry.Should().BeSameAs(original);
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_HelperStartFailure_RemainsTypedWhenVerificationFindsNoTargets()
    {
        var original = Entry(targets: [Sg, External]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(Sg, External)
            .Returns();
        var stop = new FakeStop
        {
            Failure = new AdapterStopException(
                CloseDisconnectFailureKind.ElevatedHelperStart,
                SecretFailure("helper start").Message)
        };
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(
            CloseDisconnectFailureKind.ElevatedHelperStart);
        result.UnresolvedTargets.Should().BeEmpty();
        enumerator.Calls.Should().Be(2, "verification is still required after helper failure");
        journal.Entry.Should().NotBeNull();
        journal.Entry!.Phase.Should().Be(CloseDisconnectJournalPhase.TargetsRecorded);
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_PartialStopFailure_AttemptsWholeBatchAndReturnsExactUnresolvedTargets()
    {
        var original = Entry(targets: [Sg, External]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(Sg, External)
            .Returns(External, NewAfterCrash);
        var stop = new FakeStop
        {
            Failure = new AdapterStopException(
                CloseDisconnectFailureKind.Stop,
                SecretFailure("partial stop").Message)
        };
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Stop);
        stop.Batches.Should().ContainSingle();
        stop.Batches[0].Should().BeEquivalentTo([Sg, External]);
        result.UnresolvedTargets.Should().ContainSingle().Which.Should().Be(External);
        result.UnresolvedTargets.Should().NotContain(NewAfterCrash);
        journal.Entry.Should().NotBeNull();
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_StopFailureFollowedByEnumerationFailure_PreservesPrimaryAndVerificationFailures()
    {
        var original = Entry(targets: [Sg]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(Sg)
            .Throws(SecretFailure("verification enumeration"));
        var stop = new FakeStop
        {
            Failure = new AdapterStopException(
                CloseDisconnectFailureKind.Stop,
                SecretFailure("stop").Message)
        };
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Select(failure => failure.Kind).Should().Equal(
            CloseDisconnectFailureKind.Stop,
            CloseDisconnectFailureKind.Verification);
        journal.Entry.Should().NotBeNull();
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_VerificationFailure_LeavesJournalForRetry()
    {
        var original = Entry(targets: [Sg]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(Sg)
            .Throws(SecretFailure("verification"));
        var stop = new FakeStop();
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Verification);
        stop.Batches.Should().ContainSingle();
        journal.Entry.Should().NotBeNull();
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_TargetStillInstalled_StopsAfterTenRechecksAndIgnoresUnrelatedTarget()
    {
        var original = Entry(targets: [External]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator().Returns(External);
        for (var verification = 0; verification < 11; verification++)
        {
            enumerator.Returns(External, NewAfterCrash);
        }

        var stop = new FakeStop();
        var delays = new List<TimeSpan>();
        var coordinator = CreateCoordinator(
            journal,
            enumerator,
            stop,
            delayAsync: (delay, _) =>
            {
                delays.Add(delay);
                return Task.CompletedTask;
            });

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().BeEmpty();
        result.UnresolvedTargets.Should().ContainSingle().Which.Should().Be(External);
        result.UnresolvedTargets.Should().NotContain(NewAfterCrash);
        delays.Should().HaveCount(10);
        delays.Should().AllSatisfy(delay => delay.Should().Be(TimeSpan.FromMilliseconds(200)));
        enumerator.Calls.Should().Be(12, "initial enumeration plus eleven total verifications");
        stop.Batches.Should().ContainSingle();
        stop.Batches[0].Should().ContainSingle().Which.Should().Be(External);
        journal.Entry.Should().NotBeNull();
        journal.CompleteCalls.Should().Be(0);
    }

    [Fact]
    public async Task Disconnect_RetryAfterPartialFailure_SkipsAbsentTargetsWithoutDuplicateSaveOrStop()
    {
        var original = Entry(
            phase: CloseDisconnectJournalPhase.WaitingForEnable,
            targets: [Sg, External]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(Sg, External)
            .Returns(External)
            .Returns()
            .Returns();
        var stop = new FakeStop
        {
            Failure = new AdapterStopException(CloseDisconnectFailureKind.Stop, "first attempt failed")
        };
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var first = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);
        stop.Failure = null;
        var retry = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        first.Success.Should().BeFalse();
        retry.Success.Should().BeTrue();
        stop.Batches.Should().ContainSingle("absent targets must not be stopped again");
        journal.SavedEntries.Should().ContainSingle("an unchanged complete target set is already durable");
        journal.CompleteCalls.Should().Be(1);
        journal.Entry.Should().BeNull();
    }

    [Fact]
    public async Task Prepare_PendingEnable_WritesJournalBeforeWaitingThenDisconnectStopsLateSelection()
    {
        var lateTarget = Target("late-selected");
        var enableCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var activitySource = new FakeActivitySource
        {
            Activity = new EnableTunnelActivity(lateTarget, enableCompletion.Task)
        };
        var events = new List<string>();
        var journal = new FakeJournal(events);
        var enumerator = new FakeEnumerator(events)
            .Returns(lateTarget)
            .Returns();
        var stop = new FakeStop(events);
        var operationId = Guid.NewGuid();
        var coordinator = CreateCoordinator(
            journal,
            enumerator,
            stop,
            activitySource,
            () => operationId);

        var prepareTask = coordinator.PrepareAsync(CancellationToken.None);

        prepareTask.IsCompleted.Should().BeFalse();
        activitySource.CaptureCalls.Should().Be(1);
        journal.SavedEntries.Should().ContainSingle();
        journal.SavedEntries[0].OperationId.Should().Be(operationId);
        journal.SavedEntries[0].Phase.Should().Be(CloseDisconnectJournalPhase.WaitingForEnable);
        journal.SavedEntries[0].PendingEnable.Should().Be(lateTarget);
        enableCompletion.Task.IsCompleted.Should().BeFalse();

        enableCompletion.SetResult();
        var preparation = await prepareTask.WaitAsync(TimeSpan.FromSeconds(2));
        preparation.Failure.Should().BeNull();
        var result = await coordinator.DisconnectAsync(preparation, CancellationToken.None);

        result.Success.Should().BeTrue();
        stop.Batches.Should().ContainSingle();
        stop.Batches[0].Should().ContainSingle().Which.Should().Be(lateTarget);
        journal.Entry.Should().BeNull();
    }

    [Fact]
    public async Task Prepare_ProcessIdentityPublishedDuringWait_IsDurablySavedBeforeEnableCompletion()
    {
        var pending = Target("identity-published-after-close");
        var processIdentity = ProcessIdentity();
        var enableCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var identityAvailable = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var activity = new EnableTunnelActivity(pending, enableCompletion.Task)
        {
            ProcessIdentityAvailable = identityAvailable.Task
        };
        var activitySource = new FakeActivitySource { Activity = activity };
        var journal = new FakeJournal();
        var identitySaved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        journal.Saved = () =>
        {
            if (journal.SavedEntries.Count == 2
                && journal.SavedEntries[^1].PendingEnableProcess == processIdentity)
            {
                identitySaved.TrySetResult();
            }
        };
        var coordinator = CreateCoordinator(journal, activitySource: activitySource);

        var prepareTask = coordinator.PrepareAsync(CancellationToken.None);

        journal.SavedEntries.Should().ContainSingle();
        journal.SavedEntries[0].PendingEnableProcess.Should().BeNull(
            "the pre-process-start/UAC state is explicitly preserved");
        activity.ProcessIdentity = processIdentity;
        identityAvailable.SetResult();
        await identitySaved.Task.WaitAsync(TimeSpan.FromSeconds(2));

        prepareTask.IsCompleted.Should().BeFalse("identity publication does not mean Enable completion");
        journal.Entry!.PendingEnableProcess.Should().Be(processIdentity);
        journal.Entry.PendingEnable.Should().Be(pending);

        enableCompletion.SetResult();
        (await prepareTask.WaitAsync(TimeSpan.FromSeconds(2))).Failure.Should().BeNull();
    }

    [Fact]
    public async Task Prepare_ExistingJournal_ReusesOperationAndOnlyReplacesPendingWithCurrentIdentity()
    {
        var recordedPending = Target("recorded-pending");
        var currentPending = Target("current-pending");
        var original = Entry(
            phase: CloseDisconnectJournalPhase.TargetsRecorded,
            targets: [Sg],
            pending: recordedPending);
        var enableCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var journal = new FakeJournal { Entry = original };
        var activitySource = new FakeActivitySource
        {
            Activity = new EnableTunnelActivity(currentPending, enableCompletion.Task)
        };
        var coordinator = CreateCoordinator(
            journal,
            activitySource: activitySource,
            operationIdFactory: () => throw new InvalidOperationException("A new ID must not be created."));

        var prepareTask = coordinator.PrepareAsync(CancellationToken.None);

        journal.SavedEntries.Should().ContainSingle();
        journal.SavedEntries[0].OperationId.Should().Be(original.OperationId);
        journal.SavedEntries[0].Targets.Should().Equal(Sg);
        journal.SavedEntries[0].PendingEnable.Should().Be(currentPending);
        enableCompletion.SetResult();
        (await prepareTask).Failure.Should().BeNull();

        journal.Entry = original;
        journal.SavedEntries.Clear();
        activitySource.Activity = new EnableTunnelActivity(null, enableCompletion.Task);
        await coordinator.PrepareAsync(CancellationToken.None);

        journal.SavedEntries.Should().ContainSingle();
        journal.SavedEntries[0].PendingEnable.Should().Be(
            recordedPending,
            "an identity-less capture must not erase the durable pending identity");
        journal.SavedEntries[0].OperationId.Should().Be(original.OperationId);
    }

    [Fact]
    public async Task Prepare_CloseCanceledEnable_IsExpectedAndLateTunnelCleanupSucceeds()
    {
        var lateTarget = Target("late-after-close-cancellation");
        var enableCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var activitySource = new FakeActivitySource
        {
            Activity = new EnableTunnelActivity(lateTarget, enableCompletion.Task)
        };
        var journal = new FakeJournal();
        var enumerator = new FakeEnumerator()
            .Returns(lateTarget)
            .Returns();
        var stop = new FakeStop();
        var coordinator = CreateCoordinator(journal, enumerator, stop, activitySource);
        using var closeCancellation = new CancellationTokenSource();

        var prepareTask = coordinator.PrepareAsync(closeCancellation.Token);
        journal.SavedEntries.Should().ContainSingle("the pending identity must be durable before the wait");
        closeCancellation.Cancel();
        prepareTask.IsCompleted.Should().BeFalse(
            "caller cancellation must not abandon the noncancelable elevated-process activity");

        enableCompletion.SetCanceled();
        var preparation = await prepareTask.WaitAsync(TimeSpan.FromSeconds(2));
        var result = await coordinator.DisconnectAsync(preparation, CancellationToken.None);

        preparation.Failure.Should().BeNull("close-driven Enable follow-on cancellation is expected");
        result.Success.Should().BeTrue();
        result.Failures.Should().BeEmpty();
        stop.Batches.Should().ContainSingle();
        stop.Batches[0].Should().ContainSingle().Which.Should().Be(lateTarget);
        enumerator.Calls.Should().Be(2);
        journal.Entry.Should().BeNull();
    }

    [Fact]
    public async Task Prepare_FaultedEnable_StillCleansUpButReturnsEnableWaitAndKeepsJournalForRetry()
    {
        var lateTarget = Target("late-after-enable-fault");
        var enableCompletion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        enableCompletion.SetException(SecretFailure("enable wait"));
        var activitySource = new FakeActivitySource
        {
            Activity = new EnableTunnelActivity(lateTarget, enableCompletion.Task)
        };
        var journal = new FakeJournal();
        var enumerator = new FakeEnumerator()
            .Returns(lateTarget)
            .Returns();
        var stop = new FakeStop();
        var coordinator = CreateCoordinator(journal, enumerator, stop, activitySource);

        var preparation = await coordinator.PrepareAsync(CancellationToken.None);
        var result = await coordinator.DisconnectAsync(preparation, CancellationToken.None);

        preparation.Failure.Should().NotBeNull();
        preparation.Failure!.Kind.Should().Be(CloseDisconnectFailureKind.EnableWait);
        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.EnableWait);
        result.UnresolvedTargets.Should().BeEmpty();
        enumerator.Calls.Should().Be(2, "cleanup and verification must still run after an Enable fault");
        stop.Batches.Should().ContainSingle();
        stop.Batches[0].Should().ContainSingle().Which.Should().Be(lateTarget);
        journal.Entry.Should().NotBeNull("the actual Enable failure must remain retryable");
        journal.Entry!.OperationId.Should().Be(preparation.OperationId);
        journal.Entry.Phase.Should().Be(CloseDisconnectJournalPhase.TargetsRecorded);
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_PreparationJournalOperationMismatch_FailsBeforeEnumerationOrMutation()
    {
        var original = Entry(targets: [Sg]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator();
        var stop = new FakeStop();
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.DisconnectAsync(Prepared(Guid.NewGuid()), CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Journal);
        enumerator.Calls.Should().Be(0, "identity validation precedes all cleanup work");
        stop.Batches.Should().BeEmpty();
        journal.SavedEntries.Should().BeEmpty();
        journal.CompleteCalls.Should().Be(0);
        journal.Entry.Should().BeSameAs(original);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_CompletionRaceWithReplacementJournal_FailsAndPreservesReplacement()
    {
        var original = Entry(targets: [Sg]);
        var replacement = Entry(targets: [External]);
        var journal = new FakeJournal { Entry = original };
        journal.Completing = () => journal.Entry = replacement;
        var enumerator = new FakeEnumerator()
            .Returns(Sg)
            .Returns();
        var stop = new FakeStop();
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeFalse("a mismatched Complete no-op must not be reported as finalized");
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Journal);
        journal.Entry.Should().BeSameAs(replacement);
        journal.CompleteCalls.Should().Be(1);
        stop.Batches.Should().ContainSingle();
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Reconcile_NoJournal_IsSuccessNoOpAndNeverCapturesEnable()
    {
        var journal = new FakeJournal();
        var enumerator = new FakeEnumerator();
        var stop = new FakeStop();
        var activitySource = new FakeActivitySource();
        var coordinator = CreateCoordinator(journal, enumerator, stop, activitySource);

        var result = await coordinator.ReconcileAsync(CancellationToken.None);

        result.Success.Should().BeTrue();
        activitySource.CaptureCalls.Should().Be(0);
        enumerator.Calls.Should().Be(0);
        stop.Batches.Should().BeEmpty();
        journal.SavedEntries.Should().BeEmpty();
        journal.CompleteCalls.Should().Be(0);
    }

    [Fact]
    public async Task Reconcile_RecordedExternalAndUnrelatedNewAfterCrash_StopsOnlyExternal()
    {
        var original = Entry(targets: [External]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(External, NewAfterCrash)
            .Returns(NewAfterCrash);
        var stop = new FakeStop();
        var activitySource = new FakeActivitySource();
        var coordinator = CreateCoordinator(journal, enumerator, stop, activitySource);

        var result = await coordinator.ReconcileAsync(CancellationToken.None);

        result.Success.Should().BeTrue();
        stop.Batches.Should().ContainSingle();
        stop.Batches[0].Should().ContainSingle().Which.Should().Be(External);
        activitySource.CaptureCalls.Should().Be(0);
        journal.Entry.Should().BeNull();
        journal.CompleteCalls.Should().Be(1);
    }

    [Fact]
    public async Task Reconcile_WaitingJournal_UsesOnlyRecordedTargetsAndPendingIdentityAfterSettlement()
    {
        var pending = Target("recorded-enable");
        var pendingProcess = ProcessIdentity();
        var original = Entry(
            phase: CloseDisconnectJournalPhase.WaitingForEnable,
            targets: [External],
            pending: pending,
            pendingProcess: pendingProcess);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(External, pending, NewAfterCrash)
            .Returns(NewAfterCrash);
        var stop = new FakeStop();
        var activitySource = new FakeActivitySource();
        var settlementProbe = new FakeSettlementProbe();
        var coordinator = CreateCoordinator(
            journal,
            enumerator,
            stop,
            activitySource,
            settlementProbe: settlementProbe);

        var result = await coordinator.ReconcileAsync(CancellationToken.None);

        result.Success.Should().BeTrue();
        settlementProbe.Calls.Should().ContainSingle().Which.Should().Be(pendingProcess);
        stop.Batches.Should().ContainSingle();
        stop.Batches[0].Should().BeEquivalentTo([External, pending]);
        stop.Batches[0].Should().NotContain(NewAfterCrash);
        journal.SavedEntries.Should().ContainSingle();
        journal.SavedEntries[0].Phase.Should().Be(CloseDisconnectJournalPhase.TargetsRecorded);
        activitySource.CaptureCalls.Should().Be(0);
    }

    [Fact]
    public async Task Reconcile_RunningEnableWithoutInstalledService_RetainsJournalThenRetryStopsLateInstall()
    {
        var pending = Target("installed-after-first-startup-attempt");
        var pendingProcess = ProcessIdentity();
        var original = Entry(
            phase: CloseDisconnectJournalPhase.WaitingForEnable,
            targets: [],
            pending: pending,
            pendingProcess: pendingProcess);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(pending)
            .Returns();
        var stop = new FakeStop();
        var settlementProbe = new FakeSettlementProbe().Returns(
            EnableTunnelProcessSettlement.Running,
            EnableTunnelProcessSettlement.Settled);
        var coordinator = CreateCoordinator(
            journal,
            enumerator,
            stop,
            settlementProbe: settlementProbe);

        var running = await coordinator.ReconcileAsync(CancellationToken.None);

        running.Success.Should().BeFalse("an absent service does not prove the old Enable has settled");
        running.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.EnableWait);
        journal.Entry.Should().BeSameAs(original);
        enumerator.Calls.Should().Be(0, "a running original process blocks cleanup before enumeration");
        stop.Batches.Should().BeEmpty();
        journal.CompleteCalls.Should().Be(0);

        // The old elevated process installs its selected service after the first
        // startup attempt, then exits. Retry must remove that late installation.
        var settled = await coordinator.ReconcileAsync(CancellationToken.None);

        settled.Success.Should().BeTrue();
        settlementProbe.Calls.Should().HaveCount(2);
        settlementProbe.Calls.Should().AllSatisfy(identity => identity.Should().Be(pendingProcess));
        stop.Batches.Should().ContainSingle();
        stop.Batches[0].Should().ContainSingle().Which.Should().Be(pending);
        journal.Entry.Should().BeNull();
        journal.CompleteCalls.Should().Be(1);
    }

    [Fact]
    public async Task Reconcile_PendingEnableWithoutProcessIdentity_FailsClosedBeforeEnumeration()
    {
        var original = Entry(
            phase: CloseDisconnectJournalPhase.WaitingForEnable,
            targets: [],
            pending: Target("pending-before-process-start"));
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator();
        var stop = new FakeStop();
        var settlementProbe = new FakeSettlementProbe();
        var coordinator = CreateCoordinator(
            journal,
            enumerator,
            stop,
            settlementProbe: settlementProbe);

        var result = await coordinator.ReconcileAsync(CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.EnableWait);
        settlementProbe.Calls.Should().BeEmpty();
        enumerator.Calls.Should().Be(0);
        stop.Batches.Should().BeEmpty();
        journal.Entry.Should().BeSameAs(original);
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Reconcile_SettlementUnknown_RetainsJournalWithoutCleanup()
    {
        var original = Entry(
            phase: CloseDisconnectJournalPhase.WaitingForEnable,
            targets: [],
            pending: Target("unknown-settlement"),
            pendingProcess: ProcessIdentity());
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator();
        var stop = new FakeStop();
        var settlementProbe = new FakeSettlementProbe().Returns(EnableTunnelProcessSettlement.Unknown);
        var coordinator = CreateCoordinator(
            journal,
            enumerator,
            stop,
            settlementProbe: settlementProbe);

        var result = await coordinator.ReconcileAsync(CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.EnableWait);
        enumerator.Calls.Should().Be(0);
        stop.Batches.Should().BeEmpty();
        journal.Entry.Should().BeSameAs(original);
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    [Fact]
    public void SettlementProbe_ExactRunningIdentity_ReturnsRunning()
    {
        var expected = ProcessIdentity();
        var probe = new WindowsEnableTunnelProcessSettlementProbe(
            processId => processId == expected.ProcessId ? expected : null);

        probe.Probe(expected).Should().Be(EnableTunnelProcessSettlement.Running);
    }

    [Fact]
    public void SettlementProbe_ExitedProcessNotFound_ReturnsSettled()
    {
        var expected = ProcessIdentity();
        var probe = new WindowsEnableTunnelProcessSettlementProbe(_ => null);

        probe.Probe(expected).Should().Be(EnableTunnelProcessSettlement.Settled);
    }

    [Fact]
    public void SettlementProbe_ReusedPidWithDifferentCreationTime_ReturnsSettled()
    {
        var expected = ProcessIdentity();
        var reusedPidIdentity = expected with { CreationTimeFileTimeUtc = expected.CreationTimeFileTimeUtc + 1 };
        var probe = new WindowsEnableTunnelProcessSettlementProbe(_ => reusedPidIdentity);

        probe.Probe(expected).Should().Be(EnableTunnelProcessSettlement.Settled);
    }

    [Fact]
    public void SettlementProbe_InspectionFailure_ReturnsUnknown()
    {
        var probe = new WindowsEnableTunnelProcessSettlementProbe(
            _ => throw SecretFailure("process inspection"));

        probe.Probe(ProcessIdentity()).Should().Be(EnableTunnelProcessSettlement.Unknown);
    }

    [Fact]
    public async Task Reconcile_AllRecordedTargetsAbsent_SkipsStopAndDuplicateSaveBeforeCompletion()
    {
        var original = Entry(targets: [Sg, External]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator().Returns(NewAfterCrash);
        var stop = new FakeStop();
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.ReconcileAsync(CancellationToken.None);

        result.Success.Should().BeTrue();
        enumerator.Calls.Should().Be(1);
        stop.Batches.Should().BeEmpty();
        journal.SavedEntries.Should().BeEmpty();
        journal.CompleteCalls.Should().Be(1);
        journal.Entry.Should().BeNull();
    }

    [Fact]
    public async Task Reconcile_StopFailure_PreservesTypedFailureJournalAndExactUnresolvedIdentity()
    {
        var original = Entry(targets: [External]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(External, NewAfterCrash)
            .Returns(External, NewAfterCrash);
        var stop = new FakeStop
        {
            Failure = new AdapterStopException(
                CloseDisconnectFailureKind.Stop,
                SecretFailure("startup stop").Message)
        };
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.ReconcileAsync(CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Stop);
        result.UnresolvedTargets.Should().ContainSingle().Which.Should().Be(External);
        journal.Entry.Should().NotBeNull();
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_RecordedCurrentAndPendingTargets_DeduplicateCaseInsensitively()
    {
        var recorded = WindowsTunnelServiceIdentity.FromServiceName("WireGuardTunnel$Office");
        var current = WindowsTunnelServiceIdentity.FromServiceName("wireguardtunnel$office");
        var pending = WindowsTunnelServiceIdentity.FromServiceName("WIREGUARDTUNNEL$OFFICE");
        var original = Entry(targets: [recorded], pending: pending);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(current)
            .Returns();
        var stop = new FakeStop();
        var coordinator = CreateCoordinator(journal, enumerator, stop);

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeTrue();
        stop.Batches.Should().ContainSingle();
        stop.Batches[0].Should().ContainSingle().Which.ServiceName.Should().Be(recorded.ServiceName);
        journal.SavedEntries.Should().BeEmpty("case-only target differences do not require another mutation");
    }

    [Fact]
    public async Task Disconnect_TransientUnresolvedTarget_RechecksOnceWithoutStoppingAgain()
    {
        var original = Entry(targets: [Sg]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(Sg)
            .Returns(Sg)
            .Returns();
        var stop = new FakeStop();
        var delays = new List<TimeSpan>();
        var coordinator = CreateCoordinator(
            journal,
            enumerator,
            stop,
            delayAsync: (delay, _) =>
            {
                delays.Add(delay);
                return Task.CompletedTask;
            });

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeTrue();
        result.Failures.Should().BeEmpty();
        result.UnresolvedTargets.Should().BeEmpty();
        delays.Should().Equal(TimeSpan.FromMilliseconds(200));
        enumerator.Calls.Should().Be(3, "initial enumeration, first verification, and one re-check");
        stop.Batches.Should().ContainSingle();
        journal.CompleteCalls.Should().Be(1);
        journal.Entry.Should().BeNull();
    }

    [Fact]
    public async Task Disconnect_TargetDisappearsDuringBound_StopsRecheckingImmediately()
    {
        var original = Entry(targets: [Sg]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(Sg)
            .Returns(Sg)
            .Returns(Sg)
            .Returns();
        var stop = new FakeStop();
        var delays = new List<TimeSpan>();
        var coordinator = CreateCoordinator(
            journal,
            enumerator,
            stop,
            delayAsync: (delay, _) =>
            {
                delays.Add(delay);
                return Task.CompletedTask;
            });

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeTrue();
        delays.Should().Equal(
            TimeSpan.FromMilliseconds(200),
            TimeSpan.FromMilliseconds(200));
        enumerator.Calls.Should().Be(4);
        stop.Batches.Should().ContainSingle();
        journal.CompleteCalls.Should().Be(1);
    }

    [Fact]
    public async Task Disconnect_StopFailureWithUnresolvedTarget_DoesNotRecheckOrHideFailure()
    {
        var original = Entry(targets: [Sg]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(Sg)
            .Returns(Sg);
        var stop = new FakeStop
        {
            Failure = new AdapterStopException(
                CloseDisconnectFailureKind.Stop,
                SecretFailure("stop").Message)
        };
        var delays = new List<TimeSpan>();
        var coordinator = CreateCoordinator(
            journal,
            enumerator,
            stop,
            delayAsync: (delay, _) =>
            {
                delays.Add(delay);
                return Task.CompletedTask;
            });

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Stop);
        result.UnresolvedTargets.Should().ContainSingle().Which.Should().Be(Sg);
        delays.Should().BeEmpty();
        enumerator.Calls.Should().Be(2);
        stop.Batches.Should().ContainSingle();
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_RecheckEnumerationFailure_PreservesVerificationAndLastUnresolvedTarget()
    {
        var original = Entry(targets: [Sg]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(Sg)
            .Returns(Sg)
            .Throws(SecretFailure("re-check verification"));
        var stop = new FakeStop();
        var delays = new List<TimeSpan>();
        var coordinator = CreateCoordinator(
            journal,
            enumerator,
            stop,
            delayAsync: (delay, _) =>
            {
                delays.Add(delay);
                return Task.CompletedTask;
            });

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), CancellationToken.None);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Verification);
        result.UnresolvedTargets.Should().ContainSingle().Which.Should().Be(Sg);
        delays.Should().Equal(TimeSpan.FromMilliseconds(200));
        enumerator.Calls.Should().Be(3);
        stop.Batches.Should().ContainSingle();
        journal.Entry.Should().NotBeNull();
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    [Fact]
    public async Task Disconnect_RecheckCancellation_ReturnsVerificationWithoutCompletingJournal()
    {
        var original = Entry(targets: [Sg]);
        var journal = new FakeJournal { Entry = original };
        var enumerator = new FakeEnumerator()
            .Returns(Sg)
            .Returns(Sg);
        var stop = new FakeStop();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var coordinator = CreateCoordinator(
            journal,
            enumerator,
            stop,
            delayAsync: (delay, token) => Task.Delay(delay, token));

        var result = await coordinator.DisconnectAsync(Prepared(original.OperationId), cancellation.Token);

        result.Success.Should().BeFalse();
        result.Failures.Should().ContainSingle().Which.Kind.Should().Be(CloseDisconnectFailureKind.Verification);
        result.UnresolvedTargets.Should().ContainSingle().Which.Should().Be(Sg);
        enumerator.Calls.Should().Be(2);
        stop.Batches.Should().ContainSingle();
        journal.Entry.Should().NotBeNull();
        journal.CompleteCalls.Should().Be(0);
        AssertSafeMessages(result);
    }

    private static CloseDisconnectCoordinator CreateCoordinator(
        FakeJournal? journal = null,
        FakeEnumerator? enumerator = null,
        FakeStop? stop = null,
        FakeActivitySource? activitySource = null,
        Func<Guid>? operationIdFactory = null,
        FakeSettlementProbe? settlementProbe = null,
        Func<TimeSpan, CancellationToken, Task>? delayAsync = null) =>
        new(
            enumerator ?? new FakeEnumerator(),
            stop ?? new FakeStop(),
            journal ?? new FakeJournal(),
            activitySource ?? new FakeActivitySource(),
            operationIdFactory ?? (() => Guid.NewGuid()),
            settlementProbe ?? new FakeSettlementProbe(),
            delayAsync);

    private static CloseDisconnectPreparation Prepared(Guid operationId) => new(operationId, null);

    private static CloseDisconnectJournalEntry Entry(
        CloseDisconnectJournalPhase phase = CloseDisconnectJournalPhase.TargetsRecorded,
        IReadOnlyList<WindowsTunnelServiceIdentity>? targets = null,
        WindowsTunnelServiceIdentity? pending = null,
        EnableTunnelProcessIdentity? pendingProcess = null) =>
        new(
            Guid.NewGuid(),
            phase,
            targets ?? [Sg],
            pending,
            pendingProcess);

    private static EnableTunnelProcessIdentity ProcessIdentity(
        int processId = 4242,
        long creationTimeFileTimeUtc = 123456789) =>
        new(processId, creationTimeFileTimeUtc);

    private static WindowsTunnelServiceIdentity Target(string tunnelName) =>
        WindowsTunnelServiceIdentity.FromTunnelName(tunnelName);

    private static InvalidOperationException SecretFailure(string operation) =>
        new($"{operation}: C:\\secret\\profile.conf PrivateKey=secret stdout=raw stderr=raw " +
            "wireguard.exe /uninstalltunnelservice secret");

    private static void AssertSafeMessages(CloseDisconnectResult result)
    {
        var messages = result.Failures.Select(failure => failure.Message).ToArray();
        messages.Should().NotBeEmpty();
        messages.Should().AllSatisfy(message =>
        {
            message.Should().NotBeNullOrWhiteSpace();
            message.Should().NotContain("C:\\secret");
            message.Should().NotContain("PrivateKey");
            message.Should().NotContain("stdout=raw");
            message.Should().NotContain("stderr=raw");
            message.Should().NotContain("wireguard.exe");
            message.Should().NotContain("/uninstalltunnelservice");
        });
    }

    private sealed class AdapterStopException : Exception
    {
        public AdapterStopException(CloseDisconnectFailureKind kind, string message)
            : base(message)
        {
            Kind = kind;
        }

        public CloseDisconnectFailureKind Kind { get; }
    }

    private sealed class FakeSettlementProbe : IEnableTunnelProcessSettlementProbe
    {
        private readonly Queue<EnableTunnelProcessSettlement> settlements = new();

        public List<EnableTunnelProcessIdentity> Calls { get; } = [];

        public FakeSettlementProbe Returns(params EnableTunnelProcessSettlement[] values)
        {
            foreach (var value in values) settlements.Enqueue(value);
            return this;
        }

        public EnableTunnelProcessSettlement Probe(EnableTunnelProcessIdentity processIdentity)
        {
            Calls.Add(processIdentity);
            return settlements.Count == 0
                ? EnableTunnelProcessSettlement.Settled
                : settlements.Dequeue();
        }
    }

    private sealed class FakeActivitySource : IEnableTunnelActivitySource
    {
        public EnableTunnelActivity Activity { get; set; } = new(null, Task.CompletedTask);

        public int CaptureCalls { get; private set; }

        public EnableTunnelActivity CaptureActivity()
        {
            CaptureCalls++;
            return Activity;
        }
    }

    private sealed class FakeEnumerator : IWindowsTunnelServiceEnumerator
    {
        private readonly List<string>? events;
        private readonly Queue<Func<Task<IReadOnlyList<WindowsTunnelServiceIdentity>>>> responses = new();

        public FakeEnumerator(List<string>? events = null)
        {
            this.events = events;
        }

        public int Calls { get; private set; }

        public FakeEnumerator Returns(params WindowsTunnelServiceIdentity[] targets)
        {
            responses.Enqueue(() => Task.FromResult<IReadOnlyList<WindowsTunnelServiceIdentity>>(targets));
            return this;
        }

        public FakeEnumerator Throws(Exception exception)
        {
            responses.Enqueue(() => Task.FromException<IReadOnlyList<WindowsTunnelServiceIdentity>>(exception));
            return this;
        }

        public Task<IReadOnlyList<WindowsTunnelServiceIdentity>> ListInstalledAsync(
            CancellationToken cancellationToken)
        {
            Calls++;
            events?.Add("enumerate");
            responses.Count.Should().BeGreaterThan(0, "every enumeration must be arranged deterministically");
            return responses.Dequeue()();
        }
    }

    private sealed class FakeStop : IWindowsTunnelServiceStop
    {
        private readonly List<string>? events;

        public FakeStop(List<string>? events = null)
        {
            this.events = events;
        }

        public List<IReadOnlyList<WindowsTunnelServiceIdentity>> Batches { get; } = [];

        public Exception? Failure { get; set; }

        public Task StopAndUninstallAsync(
            IReadOnlyList<WindowsTunnelServiceIdentity> targets,
            CancellationToken cancellationToken)
        {
            events?.Add("stop");
            Batches.Add(targets.ToArray());
            return Failure is null ? Task.CompletedTask : Task.FromException(Failure);
        }
    }

    private sealed class FakeJournal : ICloseDisconnectJournal
    {
        private readonly List<string>? events;

        public FakeJournal(List<string>? events = null)
        {
            this.events = events;
        }

        public CloseDisconnectJournalEntry? Entry { get; set; }

        public Exception? LoadException { get; set; }

        public Exception? SaveException { get; set; }

        public Exception? CompleteException { get; set; }

        public List<CloseDisconnectJournalEntry> SavedEntries { get; } = [];

        public int CompleteCalls { get; private set; }

        public Action? Completing { get; set; }

        public Action? Saved { get; set; }

        public CloseDisconnectJournalEntry? Load()
        {
            events?.Add("load");
            if (LoadException is not null) throw LoadException;
            return Entry;
        }

        public void Save(CloseDisconnectJournalEntry entry)
        {
            if (SaveException is not null) throw SaveException;
            events?.Add("save");
            SavedEntries.Add(entry);
            Entry = entry;
            Saved?.Invoke();
        }

        public void Complete(Guid operationId)
        {
            CompleteCalls++;
            if (CompleteException is not null) throw CompleteException;
            events?.Add("complete");
            Completing?.Invoke();
            if (Entry?.OperationId == operationId)
            {
                Entry = null;
            }
        }
    }
}
