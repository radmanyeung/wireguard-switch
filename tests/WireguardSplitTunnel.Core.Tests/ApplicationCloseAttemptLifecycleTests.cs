using FluentAssertions;
using WireguardSplitTunnel.Core.Services;
using WireguardSplitTunnel.Core.Updates;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ApplicationCloseAttemptLifecycleTests
{
    [Fact]
    public async Task RunAsync_AfterFailureDialogCancel_AllowsFreshCloseAttempt()
    {
        var harness = new CloseHarness();

        var first = harness.RunAsync();
        var failed = await first;
        failed.CanClose.Should().BeFalse();
        harness.Actions.SaveCount.Should().Be(0);
        harness.Updates.AuthorizationCount.Should().Be(0);

        // Cancel dismisses the dialog without closing or changing cleanup debt.
        // Releasing at that consumed boundary permits a later fresh attempt.
        harness.Lifecycle.Release(first);
        harness.Disconnect.Succeed = true;
        var retried = await harness.RunAsync();

        retried.CanClose.Should().BeTrue();
        harness.OrchestratorCount.Should().Be(2);
        harness.Disconnect.PrepareCount.Should().Be(2);
        harness.Disconnect.DisconnectCount.Should().Be(2);
        harness.Actions.SaveCount.Should().Be(1);
        harness.Updates.AuthorizationCount.Should().Be(1);
    }

    [Fact]
    public async Task RunAsync_AfterSecondCloseAnywayWarningDeclined_AllowsFreshCloseAttempt()
    {
        var harness = new CloseHarness();

        var first = harness.RunAsync();
        var failed = await first;
        failed.CanClose.Should().BeFalse();

        // Answering No to the second warning performs no close, save, journal
        // completion, or updater authorization. Dismissal releases the attempt.
        harness.Actions.SaveCount.Should().Be(0);
        harness.Updates.AuthorizationCount.Should().Be(0);
        harness.Lifecycle.Release(first);
        harness.Disconnect.Succeed = true;
        var retried = await harness.RunAsync();

        retried.CanClose.Should().BeTrue();
        harness.OrchestratorCount.Should().Be(2);
        harness.Disconnect.DisconnectCount.Should().Be(2);
        harness.Actions.SaveCount.Should().Be(1);
        harness.Updates.AuthorizationCount.Should().Be(1);
    }

    [Fact]
    public async Task RunAsync_InstallerMaintenanceAfterDismissedFailure_ClosesWithoutDisconnectingAgain()
    {
        var harness = new CloseHarness();

        var first = harness.RunAsync();
        var failed = await first;
        failed.CanClose.Should().BeFalse();
        harness.Disconnect.Succeed = true;

        // Maintenance transitions only after the failed result and dialog choice
        // have been consumed, so its fresh orchestrator never disconnects tunnels.
        harness.Lifecycle.Release(first);
        harness.Tracker.ResolveInstallerMaintenance();
        var maintenance = await harness.RunAsync();

        maintenance.CanClose.Should().BeTrue();
        maintenance.DisconnectResult.Should().BeNull();
        harness.OrchestratorCount.Should().Be(2);
        harness.Disconnect.PrepareCount.Should().Be(1);
        harness.Disconnect.DisconnectCount.Should().Be(1);
        harness.RestoreCount.Should().Be(1, "installer maintenance must preserve tunnels and routes");
        harness.Actions.SaveCount.Should().Be(1);
        harness.Updates.AuthorizationCount.Should().Be(0);
    }

    [Fact]
    public async Task RunAsync_RepeatedRequestsDuringActiveAttempt_JoinWithoutDuplicateMutations()
    {
        var harness = new CloseHarness();
        harness.Disconnect.Succeed = true;
        var prepareStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var allowPrepare = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Disconnect.Prepare = async _ =>
        {
            prepareStarted.TrySetResult();
            await allowPrepare.Task;
        };

        var first = harness.RunAsync();
        await prepareStarted.Task;
        var repeated = harness.RunAsync();

        repeated.Should().BeSameAs(first);
        harness.OrchestratorCount.Should().Be(1);
        harness.Disconnect.PrepareCount.Should().Be(1);

        allowPrepare.TrySetResult();
        var results = await Task.WhenAll(first, repeated);

        results[0].CanClose.Should().BeTrue();
        results[1].Should().BeSameAs(results[0]);
        harness.Disconnect.DisconnectCount.Should().Be(1);
        harness.Actions.SaveCount.Should().Be(1);
        harness.Updates.AuthorizationCount.Should().Be(1);
    }

    [Fact]
    public async Task RunAsync_CompletedButUnobservedAttempt_RemainsLatched()
    {
        var harness = new CloseHarness();
        harness.Disconnect.Succeed = true;

        var first = harness.RunAsync();
        var completed = await Task.WhenAny(first, Task.Delay(TimeSpan.FromSeconds(5)));
        completed.Should().Be(first);
        first.IsCompleted.Should().BeTrue();

        // WhenAny observes completion without consuming the close result. The
        // original handler can still be between the await and result processing.
        var repeated = harness.RunAsync();

        repeated.Should().BeSameAs(first);
        harness.OrchestratorCount.Should().Be(1);
        harness.Disconnect.DisconnectCount.Should().Be(1);
        harness.Actions.SaveCount.Should().Be(1);
        harness.Updates.AuthorizationCount.Should().Be(1);
    }

    [Fact]
    public async Task RunAsync_RepeatedRequestWhileFailureDialogOpen_RemainsLatched()
    {
        var harness = new CloseHarness();

        var first = harness.RunAsync();
        var failed = await first;
        failed.CanClose.Should().BeFalse();

        // The result has been consumed, but the failure dialog is still open.
        // Reentrant close requests join the latched attempt until a choice is dismissed.
        var repeated = harness.RunAsync();

        repeated.Should().BeSameAs(first);
        (await repeated).Should().BeSameAs(failed);
        harness.OrchestratorCount.Should().Be(1);
        harness.Disconnect.PrepareCount.Should().Be(1);
        harness.Disconnect.DisconnectCount.Should().Be(1);
        harness.Actions.SaveCount.Should().Be(0);
        harness.Updates.AuthorizationCount.Should().Be(0);
    }

    [Fact]
    public async Task RunAsync_MaintenanceArrivesWithFailedDialogLatched_TransitionsWithoutDismissal()
    {
        var harness = new CloseHarness();

        var first = harness.RunCurrentIntentAsync();
        var failed = await first;
        failed.CanClose.Should().BeFalse();

        // The failed result is latched for a user recovery dialog, but maintenance
        // takes ownership before any Retry/Close anyway/Cancel choice is made.
        harness.Tracker.ResolveInstallerMaintenance();
        var maintenanceTask = harness.RunCurrentIntentAsync();
        var maintenance = await maintenanceTask;

        maintenanceTask.Should().NotBeSameAs(first);
        maintenance.CanClose.Should().BeTrue();
        maintenance.DisconnectResult.Should().BeNull();
        harness.OrchestratorCount.Should().Be(2);
        harness.Disconnect.PrepareCount.Should().Be(1);
        harness.Disconnect.DisconnectCount.Should().Be(1);
        harness.RestoreCount.Should().Be(1);
        harness.Actions.SaveCount.Should().Be(1);
        harness.Updates.AuthorizationCount.Should().Be(0);
    }

    [Fact]
    public async Task RunAsync_MaintenanceDuringPendingDisconnect_JoinsSettlementThenTransitions()
    {
        var harness = new CloseHarness();
        var disconnectStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var allowDisconnect = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        harness.Disconnect.DisconnectOperation = async _ =>
        {
            disconnectStarted.TrySetResult();
            await allowDisconnect.Task;
            return harness.Disconnect.CreateResult();
        };

        var first = harness.RunCurrentIntentAsync();
        await disconnectStarted.Task;
        harness.Tracker.ResolveInstallerMaintenance();
        var reentrant = harness.RunCurrentIntentAsync();

        reentrant.Should().BeSameAs(first);
        harness.OrchestratorCount.Should().Be(1);
        harness.Disconnect.PrepareCount.Should().Be(1);
        harness.Disconnect.DisconnectCount.Should().Be(1);

        allowDisconnect.TrySetResult();
        var failed = await first;
        failed.CanClose.Should().BeFalse();

        var maintenanceTask = harness.RunCurrentIntentAsync();
        var maintenance = await maintenanceTask;

        maintenanceTask.Should().NotBeSameAs(first);
        maintenance.CanClose.Should().BeTrue();
        maintenance.DisconnectResult.Should().BeNull();
        harness.OrchestratorCount.Should().Be(2);
        harness.Disconnect.PrepareCount.Should().Be(1);
        harness.Disconnect.DisconnectCount.Should().Be(1);
        harness.RestoreCount.Should().Be(1);
        // The settled orchestration saves under the new maintenance intent, then
        // the explicit failed-result transition performs the final maintenance save.
        harness.Actions.SaveCount.Should().Be(2);
        harness.Updates.AuthorizationCount.Should().Be(0);
    }

    private sealed class CloseHarness
    {
        public CloseHarness()
        {
            Tracker.ResolveNormalClose();
        }

        public ApplicationCloseAttemptLifecycle Lifecycle { get; } = new();
        public ApplicationCloseIntentTracker Tracker { get; } = new();
        public FakeCloseActions Actions { get; } = new();
        public FakeUpdateParticipant Updates { get; } = new();
        public FakeDisconnectParticipant Disconnect { get; } = new();
        public int OrchestratorCount { get; private set; }
        public int RestoreCount { get; private set; }

        public Task<ApplicationCloseResult> RunAsync() =>
            Lifecycle.RunAsync(CreateOrchestrator, CancellationToken.None);

        public Task<ApplicationCloseResult> RunCurrentIntentAsync() =>
            Lifecycle.RunAsync(CreateOrchestrator, Tracker, CancellationToken.None);

        private ApplicationCloseOrchestrator CreateOrchestrator()
        {
            OrchestratorCount++;
            return new ApplicationCloseOrchestrator(
                Updates,
                Actions,
                Tracker,
                new ApplicationCloseRequest(
                    IsElevated: true,
                    IsPostInstallSelfTest: false,
                    ProcessId: 42,
                    CreationTimeFileTimeUtc: 1,
                    ImagePath: "C:\\app\\app.exe"),
                _ =>
                {
                    RestoreCount++;
                    return Task.CompletedTask;
                },
                Tracker.Current == ApplicationCloseIntent.UserOrApplicationClose
                    ? Disconnect
                    : null);
        }
    }

    private sealed class FakeCloseActions : IApplicationCloseActions
    {
        public int RunCount { get; private set; }
        public int SaveCount { get; private set; }

        public async Task RunRoutingExclusiveAsync(
            Func<CancellationToken, Task> restoreAsync,
            CancellationToken cancellationToken)
        {
            RunCount++;
            await restoreAsync(cancellationToken);
        }

        public void SavePrimaryState() => SaveCount++;
    }

    private sealed class FakeUpdateParticipant : IUpdateCloseParticipant
    {
        public int AuthorizationCount { get; private set; }

        public Task StopForCloseAsync(CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<UpdateCloseAuthorizationResult> TryAuthorizeAndLaunchAsync(
            UpdateCloseAuthorizationContext context,
            CancellationToken cancellationToken)
        {
            AuthorizationCount++;
            return Task.FromResult(
                UpdateCloseAuthorizationResult.NoProtectedTransaction());
        }
    }

    private sealed class FakeDisconnectParticipant : IUserCloseDisconnectParticipant
    {
        private static readonly WindowsTunnelServiceIdentity Unresolved =
            WindowsTunnelServiceIdentity.FromTunnelName("unresolved");

        public bool Succeed { get; set; }
        public Func<CancellationToken, Task>? Prepare { get; set; }
        public Func<CancellationToken, Task<CloseDisconnectResult>>? DisconnectOperation { get; set; }
        public int PrepareCount { get; private set; }
        public int DisconnectCount { get; private set; }

        public async Task<CloseDisconnectPreparation> PrepareAsync(
            CancellationToken cancellationToken)
        {
            PrepareCount++;
            if (Prepare is not null)
            {
                await Prepare(cancellationToken);
            }

            return new CloseDisconnectPreparation(Guid.NewGuid(), null);
        }

        public async Task<CloseDisconnectResult> DisconnectAsync(
            CloseDisconnectPreparation preparation,
            CancellationToken cancellationToken)
        {
            DisconnectCount++;
            return DisconnectOperation is null
                ? CreateResult()
                : await DisconnectOperation(cancellationToken);
        }

        public CloseDisconnectResult CreateResult() =>
            Succeed
                ? new CloseDisconnectResult(true, [], [])
                : new CloseDisconnectResult(
                    false,
                    [new CloseDisconnectFailure(
                        CloseDisconnectFailureKind.Verification,
                        "still installed")],
                    [Unresolved]);
    }
}
