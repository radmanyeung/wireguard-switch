using System.Diagnostics;
using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class EnableTunnelCoordinatorCloseTests
{
    [Fact]
    public async Task CapturedActivity_RemainsPendingThroughExitAndPropagatesFollowOnFailureAfterCleanup()
    {
        using var gate = new SemaphoreSlim(1, 1);
        var factory = new ControlledEnableTunnelProcessFactory();
        var coordinator = new EnableTunnelCoordinator(gate, factory);
        var selectedTunnel = WindowsTunnelServiceIdentity.FromTunnelName("SG");
        var started = NewCompletion();
        var followOnStarted = NewCompletion();
        var finishFollowOn = NewCompletion();
        EnableTunnelActivity? captured = null;

        var idle = coordinator.CaptureActivity();
        idle.PendingTunnel.Should().BeNull();
        idle.Completion.IsCompletedSuccessfully.Should().BeTrue();

        var run = coordinator.RunAsync(
            () => UnusedStartInfo(),
            () => true,
            () =>
            {
                captured = coordinator.CaptureActivity();
                started.SetResult();
            },
            async _ =>
            {
                followOnStarted.SetResult();
                await finishFollowOn.Task;
            },
            CancellationToken.None,
            selectedTunnel);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));

        captured.Should().NotBeNull();
        var activity = captured!;
        activity.PendingTunnel.Should().Be(selectedTunnel);
        activity.Completion.IsCompleted.Should().BeFalse();
        gate.CurrentCount.Should().Be(0);

        var process = factory.Processes.Single();
        process.Exit(0);
        IEnableTunnelProcess processContract = process;
        processContract.ExitCode.Should().Be(0);
        await followOnStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        activity.Completion.IsCompleted.Should().BeFalse(
            "process exit does not finish the follow-on renewal");
        process.DisposeCount.Should().Be(0);
        gate.CurrentCount.Should().Be(0);

        var failure = new InvalidOperationException("renewal failed");
        finishFollowOn.SetException(failure);
        var activityFailure = await Record.ExceptionAsync(
            () => activity.Completion.WaitAsync(TimeSpan.FromSeconds(2)));

        activityFailure.Should().BeSameAs(failure);
        process.WaitToken.CanBeCanceled.Should().BeFalse();
        process.DisposeCount.Should().Be(1);
        (await gate.WaitAsync(0)).Should().BeTrue(
            "the routing gate is released before observers complete");
        gate.Release();

        var runFailure = await Record.ExceptionAsync(
            () => run.WaitAsync(TimeSpan.FromSeconds(2)));
        runFailure.Should().BeSameAs(failure);
        var completed = coordinator.CaptureActivity();
        completed.PendingTunnel.Should().BeNull();
        completed.Completion.IsCompletedSuccessfully.Should().BeTrue();
    }

    [Fact]
    public async Task CapturedActivity_PublishesExactProcessIdentityAfterStartWithoutReplacingCapture()
    {
        using var gate = new SemaphoreSlim(1, 1);
        var identity = new EnableTunnelProcessIdentity(731, 987654321);
        var factory = new ControlledEnableTunnelProcessFactory
        {
            ProcessIdentity = identity
        };
        var coordinator = new EnableTunnelCoordinator(gate, factory);
        var selectedTunnel = WindowsTunnelServiceIdentity.FromTunnelName("SG");
        var started = NewCompletion();
        EnableTunnelActivity? beforeStart = null;
        factory.Starting = () =>
        {
            beforeStart = coordinator.CaptureActivity();
            beforeStart.ProcessIdentity.Should().BeNull();
            beforeStart.ProcessIdentityAvailable.IsCompleted.Should().BeFalse();
        };

        var run = coordinator.RunAsync(
            () => UnusedStartInfo(),
            () => true,
            () =>
            {
                coordinator.CaptureActivity().Should().BeSameAs(beforeStart);
                started.SetResult();
            },
            _ => Task.CompletedTask,
            CancellationToken.None,
            selectedTunnel);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));

        beforeStart.Should().NotBeNull();
        beforeStart!.PendingTunnel.Should().Be(selectedTunnel);
        beforeStart.ProcessIdentity.Should().Be(identity);
        beforeStart.ProcessIdentityAvailable.IsCompletedSuccessfully.Should().BeTrue();
        beforeStart.Completion.IsCompleted.Should().BeFalse();

        factory.Processes.Single().Exit(0);
        await run.WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task QueuedEnable_DoesNotOverwriteActiveCapturedActivity()
    {
        using var gate = new SemaphoreSlim(1, 1);
        var factory = new ControlledEnableTunnelProcessFactory();
        var coordinator = new EnableTunnelCoordinator(gate, factory);
        var firstTunnel = WindowsTunnelServiceIdentity.FromTunnelName("first");
        var secondTunnel = WindowsTunnelServiceIdentity.FromTunnelName("second");
        var firstStarted = NewCompletion();
        var secondStarted = NewCompletion();
        var finishFirstFollowOn = NewCompletion();

        var first = coordinator.RunAsync(
            () => UnusedStartInfo(),
            () => true,
            firstStarted.SetResult,
            _ => finishFirstFollowOn.Task,
            CancellationToken.None,
            firstTunnel);
        await firstStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var firstActivity = coordinator.CaptureActivity();

        var second = coordinator.RunAsync(
            () => UnusedStartInfo(),
            () => true,
            secondStarted.SetResult,
            _ => Task.CompletedTask,
            CancellationToken.None,
            secondTunnel);
        var whileQueued = coordinator.CaptureActivity();

        whileQueued.PendingTunnel.Should().Be(firstTunnel);
        whileQueued.Completion.Should().BeSameAs(firstActivity.Completion);
        factory.StartCalls.Should().Be(1);

        factory.Processes[0].Exit(0);
        finishFirstFollowOn.SetResult();
        await firstActivity.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await secondStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        var secondActivity = coordinator.CaptureActivity();
        secondActivity.PendingTunnel.Should().Be(secondTunnel);
        secondActivity.Completion.Should().NotBeSameAs(firstActivity.Completion);
        secondActivity.Completion.IsCompleted.Should().BeFalse();

        factory.Processes[1].Exit(0);
        await secondActivity.Completion.WaitAsync(TimeSpan.FromSeconds(2));
        await first.WaitAsync(TimeSpan.FromSeconds(2));
        await second.WaitAsync(TimeSpan.FromSeconds(2));
        factory.StartCalls.Should().Be(2);
    }

    [Fact]
    public async Task StartFailure_FaultsCapturedActivityAndReleasesGate()
    {
        using var gate = new SemaphoreSlim(1, 1);
        var failure = new InvalidOperationException("start failed");
        var factory = new ControlledEnableTunnelProcessFactory
        {
            StartException = failure
        };
        var coordinator = new EnableTunnelCoordinator(gate, factory);
        var selectedTunnel = WindowsTunnelServiceIdentity.FromTunnelName("SG");
        EnableTunnelActivity? captured = null;
        factory.Starting = () => captured = coordinator.CaptureActivity();

        var runFailure = await Record.ExceptionAsync(() => coordinator.RunAsync(
            () => UnusedStartInfo(),
            () => true,
            () => { },
            _ => Task.CompletedTask,
            CancellationToken.None,
            selectedTunnel));

        runFailure.Should().BeSameAs(failure);
        captured.Should().NotBeNull();
        captured!.PendingTunnel.Should().Be(selectedTunnel);
        var activityFailure = await Record.ExceptionAsync(
            () => captured.Completion.WaitAsync(TimeSpan.FromSeconds(2)));
        activityFailure.Should().BeSameAs(failure);
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
        coordinator.CaptureActivity().Completion.IsCompletedSuccessfully.Should().BeTrue();
    }

    [Fact]
    public async Task QueuedEnableRejectedBySecondCheck_NeverPublishesActivity()
    {
        using var gate = new SemaphoreSlim(1, 1);
        await gate.WaitAsync();
        var factory = new ControlledEnableTunnelProcessFactory();
        var coordinator = new EnableTunnelCoordinator(gate, factory);
        var mayStartCalls = 0;

        var run = coordinator.RunAsync(
            () => UnusedStartInfo(),
            () => ++mayStartCalls == 1,
            () => { },
            _ => Task.CompletedTask,
            CancellationToken.None,
            WindowsTunnelServiceIdentity.FromTunnelName("rejected"));
        var whileQueued = coordinator.CaptureActivity();
        gate.Release();
        await run.WaitAsync(TimeSpan.FromSeconds(2));

        whileQueued.PendingTunnel.Should().BeNull();
        whileQueued.Completion.IsCompletedSuccessfully.Should().BeTrue();
        factory.StartCalls.Should().Be(0);
        mayStartCalls.Should().Be(2);
        coordinator.CaptureActivity().PendingTunnel.Should().BeNull();
    }

    private static TaskCompletionSource NewCompletion() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static ProcessStartInfo UnusedStartInfo() =>
        new() { FileName = "not-launched-by-tests.exe" };

    private sealed class ControlledEnableTunnelProcessFactory : IEnableTunnelProcessFactory
    {
        public List<ControlledEnableTunnelProcess> Processes { get; } = [];
        public Exception? StartException { get; init; }
        public Action? Starting { get; set; }
        public EnableTunnelProcessIdentity? ProcessIdentity { get; init; }
        public int StartCalls { get; private set; }

        public IEnableTunnelProcess Start(ProcessStartInfo startInfo)
        {
            StartCalls++;
            Starting?.Invoke();
            if (StartException is not null) throw StartException;
            var process = new ControlledEnableTunnelProcess
            {
                Identity = ProcessIdentity
            };
            Processes.Add(process);
            return process;
        }
    }

    private sealed class ControlledEnableTunnelProcess : IEnableTunnelProcess
    {
        private readonly TaskCompletionSource exited = NewCompletion();

        public EnableTunnelProcessIdentity? Identity { get; init; }
        public int ExitCode { get; private set; }
        public CancellationToken WaitToken { get; private set; }
        public int DisposeCount { get; private set; }

        public Task WaitForExitAsync(CancellationToken cancellationToken)
        {
            WaitToken = cancellationToken;
            return exited.Task;
        }

        public void Exit(int exitCode)
        {
            ExitCode = exitCode;
            exited.SetResult();
        }

        public void Dispose() => DisposeCount++;
    }
}
