using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ApplicationCloseOrchestratorTests
{
    [Fact]
    public async Task RunOnceAsync_UsesTheExactSuccessfulCloseOrder()
    {
        var order = new List<string>();
        var tracker = NormalCloseTracker();
        var participant = new FakeParticipant(order: order);
        var actions = new SemaphoreCloseActions(order: order);
        var orchestrator = CreateOrchestrator(
            participant,
            actions,
            tracker,
            _ =>
            {
                order.Add("RestoreRoutes");
                return Task.CompletedTask;
            });

        var result = await orchestrator.RunOnceAsync();

        order.Should().Equal(
            "StopUpdateWork",
            "AcquireSoftware",
            "AcquireRenew",
            "RestoreRoutes",
            "SavePrimaryState",
            "ReleaseRenew",
            "ReleaseSoftware",
            "AuthorizeAndLaunch");
        result.Outcome.Should().Be(ApplicationCloseOutcome.HelperReady);
        result.CanClose.Should().BeTrue();
        participant.LastContext!.Intent.Should().Be(ApplicationCloseIntent.UserOrApplicationClose);
    }

    [Fact]
    public async Task RunOnceAsync_WaitsForIncrementalReconcileCommitBeforeRestore()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var renewGate = new SemaphoreSlim(1, 1);
        var state = new AppState(
            [new DomainRule("*.claude.ai")],
            new Dictionary<string, List<string>>(),
            []);
        var reconciler = new IncrementalDnsRouteReconciler(
            new FakeDnsCacheReader(
                [new DnsCacheEntry("downloads.claude.ai", "198.51.100.25")]));
        var routeCallbackStarted = AsyncSignal();
        var allowRouteCallback = AsyncSignal();
        var restoredIps = new List<string>();
        var actions = new SemaphoreCloseActions(softwareGate, renewGate);
        var participant = new FakeParticipant();
        var orchestrator = CreateOrchestrator(
            participant,
            actions,
            NormalCloseTracker(),
            _ =>
            {
                restoredIps.AddRange(state.ManagedRouteSnapshot.Select(entry => entry.IpAddress));
                state.ManagedRouteSnapshot.Clear();
                return Task.CompletedTask;
            });

        var reconcileTask = DomainRouteOperationSerializer.RunAsync(
            renewGate,
            () => reconciler.ReconcileAsync(
                state,
                async (_, _) =>
                {
                    routeCallbackStarted.SetResult();
                    await allowRouteCallback.Task;
                },
                CancellationToken.None));
        await routeCallbackStarted.Task;

        var closeTask = orchestrator.RunOnceAsync();
        closeTask.IsCompleted.Should().BeFalse();
        restoredIps.Should().BeEmpty();

        allowRouteCallback.SetResult();
        await reconcileTask;
        await closeTask;

        restoredIps.Should().Equal("198.51.100.25");
        state.ManagedRouteSnapshot.Should().BeEmpty();
    }

    [Fact]
    public async Task RunOnceAsync_DoesNotDeadlockBehindApplyHoldingSoftwareThenWaitingRenew()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var renewGate = new SemaphoreSlim(1, 1);
        await renewGate.WaitAsync();
        var applyHasSoftware = AsyncSignal();
        var actions = new SemaphoreCloseActions(softwareGate, renewGate);
        var orchestrator = CreateOrchestrator(
            new FakeParticipant(),
            actions,
            NormalCloseTracker());

        var applyTask = Task.Run(async () =>
        {
            await softwareGate.WaitAsync();
            applyHasSoftware.SetResult();
            await renewGate.WaitAsync();
            renewGate.Release();
            softwareGate.Release();
        });
        await applyHasSoftware.Task;

        var closeTask = orchestrator.RunOnceAsync();
        closeTask.IsCompleted.Should().BeFalse();

        renewGate.Release();
        await Task.WhenAll(applyTask, closeTask).WaitAsync(TimeSpan.FromSeconds(5));

        actions.SaveCount.Should().Be(1);
    }

    [Fact]
    public async Task RunOnceAsync_DrainsBlockedStopBeforeGatesAndAuthorization()
    {
        var stopStarted = AsyncSignal();
        var allowStop = AsyncSignal();
        var participant = new FakeParticipant(
            stop: async _ =>
            {
                stopStarted.SetResult();
                await allowStop.Task;
            });
        var actions = new SemaphoreCloseActions();
        var orchestrator = CreateOrchestrator(participant, actions, NormalCloseTracker());

        var closeTask = orchestrator.RunOnceAsync();
        await stopStarted.Task;

        actions.RunCount.Should().Be(0);
        participant.AuthorizationCount.Should().Be(0);
        closeTask.IsCompleted.Should().BeFalse();

        allowStop.SetResult();
        await closeTask;

        actions.RunCount.Should().Be(1);
        participant.AuthorizationCount.Should().Be(1);
    }

    [Fact]
    public async Task RunOnceAsync_WhenSessionEndingArrivesDuringRestore_SavesButNeverAuthorizes()
    {
        var restoreStarted = AsyncSignal();
        var allowRestore = AsyncSignal();
        var tracker = NormalCloseTracker();
        var participant = new FakeParticipant();
        var actions = new SemaphoreCloseActions();
        var orchestrator = CreateOrchestrator(
            participant,
            actions,
            tracker,
            async _ =>
            {
                restoreStarted.SetResult();
                await allowRestore.Task;
            });

        var closeTask = orchestrator.RunOnceAsync();
        await restoreStarted.Task;
        tracker.RecordSessionEnding();
        allowRestore.SetResult();

        var result = await closeTask;

        actions.SaveCount.Should().Be(1);
        participant.AuthorizationCount.Should().Be(0);
        result.Outcome.Should().Be(ApplicationCloseOutcome.NoAuthorization);
        result.Failures.Should().Be(ApplicationCloseFailureFlags.None);
    }

    [Fact]
    public async Task RunOnceAsync_WhenStopFails_StillRestoresAndSavesButSkipsAuthorization()
    {
        var restoreCalls = 0;
        var participant = new FakeParticipant(
            stop: _ => Task.FromException(new IOException("stop failed")));
        var actions = new SemaphoreCloseActions();
        var orchestrator = CreateOrchestrator(
            participant,
            actions,
            NormalCloseTracker(),
            _ =>
            {
                restoreCalls++;
                return Task.CompletedTask;
            });

        var result = await orchestrator.RunOnceAsync();

        actions.RunCount.Should().Be(1);
        restoreCalls.Should().Be(1);
        actions.SaveCount.Should().Be(1);
        participant.AuthorizationCount.Should().Be(0);
        result.Failures.Should().Be(ApplicationCloseFailureFlags.StopUpdateWork);
        result.CanClose.Should().BeTrue();
    }

    [Fact]
    public async Task RunOnceAsync_WhenRestoreFails_StillSavesAndSkipsAuthorization()
    {
        var participant = new FakeParticipant();
        var actions = new SemaphoreCloseActions();
        var orchestrator = CreateOrchestrator(
            participant,
            actions,
            NormalCloseTracker(),
            _ => Task.FromException(new IOException("restore failed")));

        var result = await orchestrator.RunOnceAsync();

        actions.SaveCount.Should().Be(1);
        participant.AuthorizationCount.Should().Be(0);
        result.Failures.Should().Be(ApplicationCloseFailureFlags.RestoreRoutes);
        result.CanClose.Should().BeTrue();
    }

    [Fact]
    public async Task RunOnceAsync_WhenSaveFails_SkipsAuthorization()
    {
        var participant = new FakeParticipant();
        var actions = new SemaphoreCloseActions
        {
            SaveException = new IOException("save failed")
        };
        var orchestrator = CreateOrchestrator(participant, actions, NormalCloseTracker());

        var result = await orchestrator.RunOnceAsync();

        actions.SaveCount.Should().Be(1);
        participant.AuthorizationCount.Should().Be(0);
        result.Failures.Should().Be(ApplicationCloseFailureFlags.SavePrimaryState);
        result.CanClose.Should().BeTrue();
    }

    [Fact]
    public async Task RunOnceAsync_WhenGateAcquisitionFails_TypesFailureAndSkipsSaveAndAuthorization()
    {
        var participant = new FakeParticipant();
        var actions = new SemaphoreCloseActions
        {
            GateException = new IOException("gate failed")
        };
        var orchestrator = CreateOrchestrator(participant, actions, NormalCloseTracker());

        var result = await orchestrator.RunOnceAsync();

        actions.RunCount.Should().Be(1);
        actions.SaveCount.Should().Be(0);
        participant.AuthorizationCount.Should().Be(0);
        result.Failures.Should().Be(ApplicationCloseFailureFlags.RoutingGate);
        result.CanClose.Should().BeTrue();
    }

    [Fact]
    public async Task RunOnceAsync_WhenCancelled_ReturnsTypedCloseCompletableResultAndSkipsAuthorization()
    {
        using var cancellationSource = new CancellationTokenSource();
        cancellationSource.Cancel();
        var participant = new FakeParticipant(
            stop: token => Task.FromCanceled(token));
        var actions = new SemaphoreCloseActions();
        var orchestrator = CreateOrchestrator(participant, actions, NormalCloseTracker());

        var result = await orchestrator.RunOnceAsync(cancellationSource.Token);

        actions.RunCount.Should().Be(1);
        participant.AuthorizationCount.Should().Be(0);
        result.Failures.Should().HaveFlag(ApplicationCloseFailureFlags.Cancelled);
        result.CanClose.Should().BeTrue();
    }

    [Fact]
    public async Task RunOnceAsync_WaitsUntilHelperReportsReady()
    {
        var helperReady = new TaskCompletionSource<UpdateCloseAuthorizationResult>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var participant = new FakeParticipant(
            authorize: (_, _) => helperReady.Task);
        var orchestrator = CreateOrchestrator(
            participant,
            new SemaphoreCloseActions(),
            NormalCloseTracker());

        var closeTask = orchestrator.RunOnceAsync();
        await participant.AuthorizationStarted.Task;

        closeTask.IsCompleted.Should().BeFalse();

        helperReady.SetResult(UpdateCloseAuthorizationResult.HelperReady());
        var result = await closeTask;

        result.Outcome.Should().Be(ApplicationCloseOutcome.HelperReady);
    }

    [Fact]
    public async Task RunOnceAsync_PreservesReturnedRecoverableAuthorizationResult()
    {
        var recoverable = UpdateCloseAuthorizationResult.RecoverableFailure("ready_timeout");
        var participant = new FakeParticipant(
            authorize: (_, _) => Task.FromResult(recoverable));
        var orchestrator = CreateOrchestrator(
            participant,
            new SemaphoreCloseActions(),
            NormalCloseTracker());

        var result = await orchestrator.RunOnceAsync();

        result.Outcome.Should().Be(ApplicationCloseOutcome.RecoverableAuthorizationFailure);
        result.AuthorizationResult.Should().BeSameAs(recoverable);
        result.Failures.Should().Be(ApplicationCloseFailureFlags.None);
    }

    [Fact]
    public async Task RunOnceAsync_TypesRaisedHelperReadyFailureAsRecoverable()
    {
        var participant = new FakeParticipant(
            authorize: (_, _) => Task.FromException<UpdateCloseAuthorizationResult>(
                new IOException("READY failed")));
        var orchestrator = CreateOrchestrator(
            participant,
            new SemaphoreCloseActions(),
            NormalCloseTracker());

        var result = await orchestrator.RunOnceAsync();

        result.Outcome.Should().Be(ApplicationCloseOutcome.RecoverableAuthorizationFailure);
        result.AuthorizationResult!.Outcome.Should().Be(UpdateCloseAuthorizationOutcome.RecoverableFailure);
        result.AuthorizationResult.ErrorCode.Should().Be("helper_ready_failed");
        result.Failures.Should().Be(ApplicationCloseFailureFlags.AuthorizationOrHelper);
        result.CanClose.Should().BeTrue();
    }

    [Fact]
    public async Task RunOnceAsync_NoProtectedTransactionIsSuccessfulNoOp()
    {
        var noTransaction = UpdateCloseAuthorizationResult.NoProtectedTransaction();
        var participant = new FakeParticipant(
            authorize: (_, _) => Task.FromResult(noTransaction));
        var orchestrator = CreateOrchestrator(
            participant,
            new SemaphoreCloseActions(),
            NormalCloseTracker());

        var result = await orchestrator.RunOnceAsync();

        result.Outcome.Should().Be(ApplicationCloseOutcome.NoProtectedTransaction);
        result.AuthorizationResult.Should().BeSameAs(noTransaction);
        result.Failures.Should().Be(ApplicationCloseFailureFlags.None);
        result.CanClose.Should().BeTrue();
    }

    [Theory]
    [InlineData(ApplicationCloseIntent.UnknownOrAbnormal, true, false, 42, 1L, "C:\\app\\app.exe")]
    [InlineData(ApplicationCloseIntent.SessionEnding, true, false, 42, 1L, "C:\\app\\app.exe")]
    [InlineData(ApplicationCloseIntent.ElevationHandoff, true, false, 42, 1L, "C:\\app\\app.exe")]
    [InlineData(ApplicationCloseIntent.UserOrApplicationClose, false, false, 42, 1L, "C:\\app\\app.exe")]
    [InlineData(ApplicationCloseIntent.UserOrApplicationClose, true, true, 42, 1L, "C:\\app\\app.exe")]
    [InlineData(ApplicationCloseIntent.UserOrApplicationClose, true, false, 0, 1L, "C:\\app\\app.exe")]
    [InlineData(ApplicationCloseIntent.UserOrApplicationClose, true, false, 42, 0L, "C:\\app\\app.exe")]
    [InlineData(ApplicationCloseIntent.UserOrApplicationClose, true, false, 42, 1L, "app.exe")]
    public async Task RunOnceAsync_InvalidOrIneligibleFinalContextSkipsAuthorization(
        ApplicationCloseIntent intent,
        bool elevated,
        bool selfTest,
        int processId,
        long creationTime,
        string imagePath)
    {
        var participant = new FakeParticipant();
        var tracker = TrackerWith(intent);
        var request = new ApplicationCloseRequest(
            elevated,
            selfTest,
            processId,
            creationTime,
            imagePath);
        var orchestrator = CreateOrchestrator(
            participant,
            new SemaphoreCloseActions(),
            tracker,
            request: request);

        var result = await orchestrator.RunOnceAsync();

        participant.AuthorizationCount.Should().Be(0);
        result.Outcome.Should().Be(ApplicationCloseOutcome.NoAuthorization);
        result.Failures.Should().Be(ApplicationCloseFailureFlags.None);
    }

    [Fact]
    public async Task RunOnceAsync_SimultaneousAndRepeatedCallersReceiveSameTaskAndExecuteOnce()
    {
        var allowStop = AsyncSignal();
        var participant = new FakeParticipant(stop: _ => allowStop.Task);
        var actions = new SemaphoreCloseActions();
        var orchestrator = CreateOrchestrator(participant, actions, NormalCloseTracker());
        const int callerCount = 16;
        using var barrier = new Barrier(callerCount);
        var returnedTasks = new Task<ApplicationCloseResult>?[callerCount];

        var callers = Enumerable.Range(0, callerCount)
            .Select(index => Task.Run(() =>
            {
                barrier.SignalAndWait();
                returnedTasks[index] = orchestrator.RunOnceAsync();
            }))
            .ToArray();
        await Task.WhenAll(callers);

        returnedTasks.Should().OnlyContain(task => ReferenceEquals(task, returnedTasks[0]));
        participant.StopCount.Should().Be(1);

        allowStop.SetResult();
        await returnedTasks[0]!;

        orchestrator.RunOnceAsync().Should().BeSameAs(returnedTasks[0]);
        participant.StopCount.Should().Be(1);
        actions.RunCount.Should().Be(1);
        participant.AuthorizationCount.Should().Be(1);
    }

    [Fact]
    public async Task RunOnceAsync_FirstCallerCancellationTokenOwnsCachedRun()
    {
        using var firstSource = new CancellationTokenSource();
        using var secondSource = new CancellationTokenSource();
        var participant = new FakeParticipant();
        var orchestrator = CreateOrchestrator(
            participant,
            new SemaphoreCloseActions(),
            NormalCloseTracker());

        var first = orchestrator.RunOnceAsync(firstSource.Token);
        var second = orchestrator.RunOnceAsync(secondSource.Token);
        await first;

        second.Should().BeSameAs(first);
        participant.StopToken.Should().Be(firstSource.Token);
        participant.AuthorizationToken.Should().Be(firstSource.Token);
    }

    [Fact]
    public async Task RunOnceAsync_DoesNotInvokeParticipantWhileHoldingTaskCacheLock()
    {
        ApplicationCloseOrchestrator? orchestrator = null;
        Task<ApplicationCloseResult>? reenteredTask = null;
        var participant = new FakeParticipant(
            stop: _ =>
            {
                reenteredTask = orchestrator!.RunOnceAsync();
                return Task.CompletedTask;
            });
        orchestrator = CreateOrchestrator(
            participant,
            new SemaphoreCloseActions(),
            NormalCloseTracker());

        var outerTask = orchestrator.RunOnceAsync();
        await outerTask.WaitAsync(TimeSpan.FromSeconds(5));

        reenteredTask.Should().BeSameAs(outerTask);
        participant.StopCount.Should().Be(1);
    }

    [Fact]
    public async Task RunOnceAsync_UnexpectedStopExceptionIsTypedAndCloseCompletable()
    {
        var participant = new FakeParticipant(
            stop: _ => Task.FromException(new InvalidOperationException("ordinary")));
        var actions = new SemaphoreCloseActions();
        var orchestrator = CreateOrchestrator(participant, actions, NormalCloseTracker());

        var result = await orchestrator.RunOnceAsync();

        result.Failures.Should().Be(ApplicationCloseFailureFlags.StopUpdateWork);
        result.CanClose.Should().BeTrue();
        actions.SaveCount.Should().Be(1);
        participant.AuthorizationCount.Should().Be(0);
    }

    [Fact]
    public async Task RunOnceAsync_UnexpectedRoutingGateExceptionIsTypedAndCloseCompletable()
    {
        var participant = new FakeParticipant();
        var actions = new SemaphoreCloseActions
        {
            GateException = new ObjectDisposedException("gate")
        };
        var orchestrator = CreateOrchestrator(participant, actions, NormalCloseTracker());

        var result = await orchestrator.RunOnceAsync();

        result.Failures.Should().Be(ApplicationCloseFailureFlags.RoutingGate);
        result.CanClose.Should().BeTrue();
        actions.SaveCount.Should().Be(0);
        participant.AuthorizationCount.Should().Be(0);
    }

    [Fact]
    public async Task RunOnceAsync_UnexpectedRestoreExceptionStillSavesAndIsCloseCompletable()
    {
        var participant = new FakeParticipant();
        var actions = new SemaphoreCloseActions();
        var orchestrator = CreateOrchestrator(
            participant,
            actions,
            NormalCloseTracker(),
            _ => Task.FromException(new NullReferenceException("ordinary")));

        var result = await orchestrator.RunOnceAsync();

        result.Failures.Should().Be(ApplicationCloseFailureFlags.RestoreRoutes);
        result.CanClose.Should().BeTrue();
        actions.SaveCount.Should().Be(1);
        participant.AuthorizationCount.Should().Be(0);
    }

    [Fact]
    public async Task RunOnceAsync_UnexpectedSaveExceptionIsTypedAndCloseCompletable()
    {
        var participant = new FakeParticipant();
        var actions = new SemaphoreCloseActions
        {
            SaveException = new ArgumentException("ordinary")
        };
        var orchestrator = CreateOrchestrator(participant, actions, NormalCloseTracker());

        var result = await orchestrator.RunOnceAsync();

        result.Failures.Should().Be(ApplicationCloseFailureFlags.SavePrimaryState);
        result.CanClose.Should().BeTrue();
        participant.AuthorizationCount.Should().Be(0);
    }

    [Fact]
    public async Task RunOnceAsync_UnexpectedAuthorizationExceptionIsRecoverableAndCloseCompletable()
    {
        var participant = new FakeParticipant(
            authorize: (_, _) => Task.FromException<UpdateCloseAuthorizationResult>(
                new InvalidOperationException("ordinary")));
        var orchestrator = CreateOrchestrator(
            participant,
            new SemaphoreCloseActions(),
            NormalCloseTracker());

        var result = await orchestrator.RunOnceAsync();

        result.Outcome.Should().Be(ApplicationCloseOutcome.RecoverableAuthorizationFailure);
        result.Failures.Should().Be(ApplicationCloseFailureFlags.AuthorizationOrHelper);
        result.AuthorizationResult!.ErrorCode.Should().Be("helper_ready_failed");
        result.CanClose.Should().BeTrue();
    }

    [Fact]
    public async Task RunOnceAsync_NullParticipantResultIsRecoverableAndCloseCompletable()
    {
        var participant = new FakeParticipant(
            authorize: (_, _) => Task.FromResult<UpdateCloseAuthorizationResult>(null!));
        var orchestrator = CreateOrchestrator(
            participant,
            new SemaphoreCloseActions(),
            NormalCloseTracker());

        var result = await orchestrator.RunOnceAsync();

        result.Outcome.Should().Be(ApplicationCloseOutcome.RecoverableAuthorizationFailure);
        result.Failures.Should().Be(ApplicationCloseFailureFlags.AuthorizationOrHelper);
        result.AuthorizationResult!.ErrorCode.Should().Be("helper_ready_failed");
        result.CanClose.Should().BeTrue();
    }

    [Fact]
    public async Task RunOnceAsync_OutOfMemoryExceptionPropagatesAsGenuinelyFatal()
    {
        var participant = new FakeParticipant(
            stop: _ => Task.FromException(new OutOfMemoryException("fatal")));
        var orchestrator = CreateOrchestrator(
            participant,
            new SemaphoreCloseActions(),
            NormalCloseTracker());

        Func<Task> run = () => orchestrator.RunOnceAsync();

        await run.Should().ThrowAsync<OutOfMemoryException>().WithMessage("fatal");
    }

    private static ApplicationCloseOrchestrator CreateOrchestrator(
        FakeParticipant participant,
        SemaphoreCloseActions actions,
        ApplicationCloseIntentTracker tracker,
        Func<CancellationToken, Task>? restore = null,
        ApplicationCloseRequest? request = null) =>
        new(
            participant,
            actions,
            tracker,
            request ?? ValidRequest(),
            restore ?? (_ => Task.CompletedTask));

    private static ApplicationCloseRequest ValidRequest() =>
        new(true, false, 42, 1, "C:\\app\\app.exe");

    private static ApplicationCloseIntentTracker NormalCloseTracker() =>
        TrackerWith(ApplicationCloseIntent.UserOrApplicationClose);

    private static ApplicationCloseIntentTracker TrackerWith(ApplicationCloseIntent intent)
    {
        var tracker = new ApplicationCloseIntentTracker();
        switch (intent)
        {
            case ApplicationCloseIntent.UserOrApplicationClose:
                tracker.ResolveNormalClose();
                break;
            case ApplicationCloseIntent.SessionEnding:
                tracker.RecordSessionEnding();
                break;
            case ApplicationCloseIntent.ElevationHandoff:
                tracker.RecordElevationHandoff();
                break;
        }

        return tracker;
    }

    private static TaskCompletionSource AsyncSignal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private sealed class FakeParticipant(
        Func<CancellationToken, Task>? stop = null,
        Func<UpdateCloseAuthorizationContext, CancellationToken, Task<UpdateCloseAuthorizationResult>>? authorize = null,
        List<string>? order = null)
        : IUpdateCloseParticipant
    {
        private readonly Func<CancellationToken, Task> _stop =
            stop ?? (_ => Task.CompletedTask);
        private readonly Func<UpdateCloseAuthorizationContext, CancellationToken, Task<UpdateCloseAuthorizationResult>> _authorize =
            authorize ?? ((_, _) => Task.FromResult(UpdateCloseAuthorizationResult.HelperReady()));

        public int StopCount { get; private set; }
        public int AuthorizationCount { get; private set; }
        public CancellationToken StopToken { get; private set; }
        public CancellationToken AuthorizationToken { get; private set; }
        public UpdateCloseAuthorizationContext? LastContext { get; private set; }
        public TaskCompletionSource AuthorizationStarted { get; } = AsyncSignal();

        public Task StopForCloseAsync(CancellationToken cancellationToken)
        {
            StopCount++;
            StopToken = cancellationToken;
            order?.Add("StopUpdateWork");
            return _stop(cancellationToken);
        }

        public Task<UpdateCloseAuthorizationResult> TryAuthorizeAndLaunchAsync(
            UpdateCloseAuthorizationContext context,
            CancellationToken cancellationToken)
        {
            AuthorizationCount++;
            AuthorizationToken = cancellationToken;
            LastContext = context;
            order?.Add("AuthorizeAndLaunch");
            AuthorizationStarted.TrySetResult();
            return _authorize(context, cancellationToken);
        }
    }

    private sealed class SemaphoreCloseActions : IApplicationCloseActions
    {
        private readonly SemaphoreSlim _softwareGate;
        private readonly SemaphoreSlim _renewGate;
        private readonly List<string>? _order;

        public SemaphoreCloseActions(
            SemaphoreSlim? softwareGate = null,
            SemaphoreSlim? renewGate = null,
            List<string>? order = null)
        {
            _softwareGate = softwareGate ?? new SemaphoreSlim(1, 1);
            _renewGate = renewGate ?? new SemaphoreSlim(1, 1);
            _order = order;
        }

        public Exception? GateException { get; init; }
        public Exception? SaveException { get; init; }
        public int RunCount { get; private set; }
        public int SaveCount { get; private set; }

        public async Task RunRoutingExclusiveAsync(
            Func<CancellationToken, Task> restoreAsync,
            CancellationToken cancellationToken)
        {
            RunCount++;
            if (GateException is not null)
            {
                throw GateException;
            }

            await _softwareGate.WaitAsync(cancellationToken);
            _order?.Add("AcquireSoftware");
            try
            {
                await _renewGate.WaitAsync(cancellationToken);
                _order?.Add("AcquireRenew");
                try
                {
                    await restoreAsync(cancellationToken);
                }
                finally
                {
                    _order?.Add("ReleaseRenew");
                    _renewGate.Release();
                }
            }
            finally
            {
                _order?.Add("ReleaseSoftware");
                _softwareGate.Release();
            }
        }

        public void SavePrimaryState()
        {
            SaveCount++;
            _order?.Add("SavePrimaryState");
            if (SaveException is not null)
            {
                throw SaveException;
            }
        }
    }

    private sealed class FakeDnsCacheReader(IReadOnlyCollection<DnsCacheEntry> entries)
        : IDnsCacheReader
    {
        public Task<IReadOnlyCollection<DnsCacheEntry>> ReadAsync(
            CancellationToken cancellationToken) =>
            Task.FromResult(entries);
    }
}
