using System.Diagnostics;
using FluentAssertions;
using WireguardSplitTunnel.Core.ConfigCheck;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ConfigCheckCoordinatorTests
{
    [Fact]
    public async Task WarningCancellation_SkipsWorkflowAndRestoresOneFlightWithoutTouchingControls()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var closeCount = 0;
        var workflowCount = 0;
        var controls = new List<bool>();
        var coordinator = new ConfigCheckCoordinator(softwareGate, gate, () => closeCount++);

        var completed = await coordinator.RunAsync(
            _ => Task.FromResult(false),
            _ =>
            {
                workflowCount++;
                return Task.CompletedTask;
            },
            _ => Task.CompletedTask,
            controls.Add,
            CancellationToken.None);

        completed.Should().BeFalse();
        workflowCount.Should().Be(0);
        controls.Should().BeEmpty();
        closeCount.Should().Be(0);
        coordinator.IsActive.Should().BeFalse();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task CloseDuringWarning_CancelsRunAndRepeatedCloseResumesExactlyOnce()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var warning = NewCompletion();
        var closeCount = 0;
        var workflowCount = 0;
        var controls = new List<bool>();
        var coordinator = new ConfigCheckCoordinator(softwareGate, gate, () => closeCount++);

        var run = coordinator.RunAsync(
            async _ =>
            {
                await warning.Task;
                return true;
            },
            _ =>
            {
                workflowCount++;
                return Task.CompletedTask;
            },
            _ => Task.CompletedTask,
            controls.Add,
            CancellationToken.None);

        coordinator.IsActive.Should().BeTrue();
        coordinator.TryDeferClose().Should().BeTrue();
        coordinator.TryDeferClose().Should().BeTrue();
        warning.SetResult();
        (await run).Should().BeFalse();

        workflowCount.Should().Be(0);
        controls.Should().BeEmpty();
        closeCount.Should().Be(1);
        coordinator.IsActive.Should().BeFalse();
    }

    [Fact]
    public async Task ExistingRenewal_DelaysStopOriginalUntilGateReleaseAndCloseWaitsForRestore()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        await gate.WaitAsync();
        var controlsDisabled = NewCompletion();
        var stopOriginal = NewCompletion();
        var finishPrimary = NewCompletion();
        var restoreStarted = NewCompletion();
        var finishRestore = NewCompletion();
        var restored = NewCompletion();
        var closeCount = 0;
        var controls = new List<bool>();
        var coordinator = new ConfigCheckCoordinator(softwareGate, gate, () => closeCount++);

        var run = coordinator.RunAsync(
            _ => Task.FromResult(true),
            async _ =>
            {
                stopOriginal.SetResult();
                try
                {
                    await finishPrimary.Task;
                }
                finally
                {
                    restoreStarted.SetResult();
                    await finishRestore.Task;
                    restored.SetResult();
                }
            },
            _ => Task.CompletedTask,
            enabled =>
            {
                controls.Add(enabled);
                if (!enabled) controlsDisabled.SetResult();
            },
            CancellationToken.None);

        await controlsDisabled.Task.WaitAsync(TimeSpan.FromSeconds(2));
        stopOriginal.Task.IsCompleted.Should().BeFalse("an existing renewal still owns the shared routing gate");
        gate.Release();
        await stopOriginal.Task.WaitAsync(TimeSpan.FromSeconds(2));

        coordinator.TryDeferClose().Should().BeTrue();
        coordinator.TryDeferClose().Should().BeTrue();
        finishPrimary.SetResult();
        await restoreStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        closeCount.Should().Be(0);
        (await gate.WaitAsync(0)).Should().BeFalse("the config workflow owns the gate through restoration");

        finishRestore.SetResult();
        (await run).Should().BeFalse();
        restored.Task.IsCompleted.Should().BeTrue();
        closeCount.Should().Be(1);
        controls.Should().Equal(false);
        (await gate.WaitAsync(0)).Should().BeTrue("restoration completed before the gate was released");
        gate.Release();
    }

    [Fact]
    public async Task ExistingSoftwareApply_DelaysStopOriginalAndBothGatesCoverWorkflowAndCompletion()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var controlsDisabled = NewCompletion();
        var stopOriginal = NewCompletion();
        var coordinator = new ConfigCheckCoordinator(softwareGate, gate, () => { });
        await softwareGate.WaitAsync();

        var run = coordinator.RunAsync(
            _ => Task.FromResult(true),
            _ =>
            {
                softwareGate.CurrentCount.Should().Be(0);
                gate.CurrentCount.Should().Be(0);
                stopOriginal.SetResult();
                return Task.CompletedTask;
            },
            _ =>
            {
                softwareGate.CurrentCount.Should().Be(0);
                gate.CurrentCount.Should().Be(0);
                return Task.CompletedTask;
            },
            enabled =>
            {
                if (!enabled) controlsDisabled.SetResult();
            });

        await controlsDisabled.Task.WaitAsync(TimeSpan.FromSeconds(2));
        stopOriginal.Task.IsCompleted.Should().BeFalse(
            "stopping the original service must wait for the in-flight software apply");
        gate.CurrentCount.Should().Be(1, "software must always be acquired before routing");
        softwareGate.Release();
        await stopOriginal.Task.WaitAsync(TimeSpan.FromSeconds(2));
        (await run).Should().BeTrue();

        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task CancellationWhileWaitingForSoftwareApply_DoesNotTouchRoutingAndAllowsRetry()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        using var cancellation = new CancellationTokenSource();
        var controlsDisabled = NewCompletion();
        var workflowCount = 0;
        var coordinator = new ConfigCheckCoordinator(softwareGate, gate, () => { });
        await softwareGate.WaitAsync();

        var run = coordinator.RunAsync(
            _ => Task.FromResult(true),
            _ =>
            {
                workflowCount++;
                return Task.CompletedTask;
            },
            _ => Task.CompletedTask,
            enabled =>
            {
                if (!enabled) controlsDisabled.SetResult();
            },
            cancellation.Token);
        await controlsDisabled.Task.WaitAsync(TimeSpan.FromSeconds(2));
        cancellation.Cancel();

        (await run).Should().BeFalse();
        workflowCount.Should().Be(0);
        softwareGate.CurrentCount.Should().Be(0, "the external apply still owns the software gate");
        gate.CurrentCount.Should().Be(1, "a canceled software wait must not acquire or release routing");
        softwareGate.Release();
        (await coordinator.RunAsync(
            _ => Task.FromResult(false),
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            _ => { })).Should().BeFalse();
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task CloseDuringRecycleCompletion_DeferredCloseStillResumesExactlyOnce()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var recycleStarted = NewCompletion();
        var finishRecycle = NewCompletion();
        var closeCount = 0;
        var controls = new List<bool>();
        var coordinator = new ConfigCheckCoordinator(softwareGate, gate, () => closeCount++);

        var run = coordinator.RunAsync(
            _ => Task.FromResult(true),
            _ => Task.CompletedTask,
            async _ =>
            {
                recycleStarted.SetResult();
                await finishRecycle.Task;
            },
            controls.Add,
            CancellationToken.None);

        await recycleStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        coordinator.TryDeferClose().Should().BeTrue();
        coordinator.TryDeferClose().Should().BeTrue();
        closeCount.Should().Be(0);
        finishRecycle.SetResult();
        (await run).Should().BeFalse();

        closeCount.Should().Be(1);
        controls.Should().Equal(false);
        coordinator.IsActive.Should().BeFalse();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task RestorationFailure_ReleasesGateAndResumesCloseWithoutSecondRestoration()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var restoreStarted = NewCompletion();
        var failRestore = NewCompletion();
        var closeCount = 0;
        var completionCount = 0;
        var coordinator = new ConfigCheckCoordinator(softwareGate, gate, () => closeCount++);

        var run = coordinator.RunAsync(
            _ => Task.FromResult(true),
            async _ =>
            {
                restoreStarted.SetResult();
                await failRestore.Task;
                throw new InvalidOperationException("restore failed");
            },
            _ =>
            {
                completionCount++;
                return Task.CompletedTask;
            },
            _ => { },
            CancellationToken.None);

        await restoreStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        coordinator.TryDeferClose().Should().BeTrue();
        failRestore.SetResult();
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => run);

        failure.Message.Should().Be("restore failed");
        completionCount.Should().Be(0);
        closeCount.Should().Be(1);
        coordinator.IsActive.Should().BeFalse();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task WorkflowFailureWithoutClose_RestoresControlsAndAllowsAnotherRun()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var closeCount = 0;
        var controls = new List<bool>();
        var coordinator = new ConfigCheckCoordinator(softwareGate, gate, () => closeCount++);

        await Assert.ThrowsAsync<InvalidOperationException>(() => coordinator.RunAsync(
            _ => Task.FromResult(true),
            _ => throw new InvalidOperationException("workflow failed"),
            _ => Task.CompletedTask,
            controls.Add,
            CancellationToken.None));

        controls.Should().Equal(false, true);
        closeCount.Should().Be(0);
        coordinator.IsActive.Should().BeFalse();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();

        (await coordinator.RunAsync(
            _ => Task.FromResult(false),
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            controls.Add,
            CancellationToken.None)).Should().BeFalse();
    }

    [Fact]
    public async Task SecondRun_IsRejectedWhileFirstWarningIsPending()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var warning = NewCompletion();
        var coordinator = new ConfigCheckCoordinator(softwareGate, gate, () => { });
        var first = coordinator.RunAsync(
            async _ =>
            {
                await warning.Task;
                return true;
            },
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            _ => { },
            CancellationToken.None);

        (await coordinator.RunAsync(
            _ => Task.FromResult(true),
            _ => Task.CompletedTask,
            _ => Task.CompletedTask,
            _ => { },
            CancellationToken.None)).Should().BeFalse();

        warning.SetResult();
        (await first).Should().BeTrue();
    }

    [Fact]
    public async Task ConfigCheck_WaitsForEnableProcessExitAndFollowOnRenewal()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var factory = new FakeEnableTunnelProcessFactory();
        var enable = new EnableTunnelCoordinator(gate, factory);
        var followOnStarted = NewCompletion();
        var finishFollowOn = NewCompletion();
        var stopOriginal = NewCompletion();
        var enableStarted = NewCompletion();
        var enableTask = enable.RunAsync(
            () => UnusedStartInfo(),
            () => true,
            enableStarted.SetResult,
            async _ =>
            {
                followOnStarted.SetResult();
                await finishFollowOn.Task;
            },
            CancellationToken.None);
        await enableStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        var config = new ConfigCheckCoordinator(softwareGate, gate, () => { });
        var configTask = config.RunAsync(
            _ => Task.FromResult(true),
            _ =>
            {
                stopOriginal.SetResult();
                return Task.CompletedTask;
            },
            _ => Task.CompletedTask,
            _ => { },
            CancellationToken.None);

        stopOriginal.Task.IsCompleted.Should().BeFalse();
        factory.Process.Exit();
        await followOnStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        stopOriginal.Task.IsCompleted.Should().BeFalse("follow-on renewal is part of the enable mutation lifetime");

        finishFollowOn.SetResult();
        await stopOriginal.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await enableTask;
        (await configTask).Should().BeTrue();
        factory.Process.DisposeCount.Should().Be(1);
    }

    [Fact]
    public async Task EnableStartFailure_ReleasesSharedGate()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var factory = new FakeEnableTunnelProcessFactory
        {
            StartException = new InvalidOperationException("start failed")
        };
        var enable = new EnableTunnelCoordinator(gate, factory);

        await Assert.ThrowsAsync<InvalidOperationException>(() => enable.RunAsync(
            () => UnusedStartInfo(),
            () => true,
            () => { },
            _ => Task.CompletedTask,
            CancellationToken.None));

        factory.StartCalls.Should().Be(1);
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task EnableCloseCancellation_StillTracksProcessThroughExitBeforeReleasingGate()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        using var cancellation = new CancellationTokenSource();
        var factory = new FakeEnableTunnelProcessFactory();
        var enable = new EnableTunnelCoordinator(gate, factory);
        var started = NewCompletion();
        var enableTask = enable.RunAsync(
            () => UnusedStartInfo(),
            () => true,
            started.SetResult,
            token =>
            {
                token.ThrowIfCancellationRequested();
                return Task.CompletedTask;
            },
            cancellation.Token);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));

        cancellation.Cancel();
        enableTask.IsCompleted.Should().BeFalse("cancellation must not abandon a running elevated process");
        (await gate.WaitAsync(0)).Should().BeFalse();
        factory.Process.Exit();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => enableTask);

        factory.Process.WaitToken.CanBeCanceled.Should().BeFalse();
        factory.Process.DisposeCount.Should().Be(1);
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task QueuedEnable_RechecksPermissionAfterGateWaitAndDoesNotStartWhenRejected()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        await gate.WaitAsync();
        var factory = new FakeEnableTunnelProcessFactory();
        var enable = new EnableTunnelCoordinator(gate, factory);
        var mayStartCalls = 0;

        var run = enable.RunAsync(
            () => UnusedStartInfo(),
            () => ++mayStartCalls == 1,
            () => { },
            _ => Task.CompletedTask,
            CancellationToken.None);
        mayStartCalls.Should().Be(1);
        gate.Release();
        await run;

        mayStartCalls.Should().Be(2);
        factory.StartCalls.Should().Be(0);
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task DeferredCloseResume_ReenteredCloseStartsNormalCloseExactlyOnce()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var workflowStarted = NewCompletion();
        var finishWorkflow = NewCompletion();
        var controls = new List<bool>();
        var normalCloseCount = 0;
        ConfigCheckCoordinator? coordinator = null;
        coordinator = new ConfigCheckCoordinator(softwareGate, gate, () =>
        {
            var deferAgain = coordinator!.TryDeferClose();
            deferAgain.Should().BeFalse("the completed config run must hand off to normal window closing");
            if (!deferAgain) normalCloseCount++;
        });

        var run = coordinator.RunAsync(
            _ => Task.FromResult(true),
            async _ =>
            {
                workflowStarted.SetResult();
                await finishWorkflow.Task;
            },
            _ => Task.CompletedTask,
            controls.Add,
            CancellationToken.None);

        await workflowStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        coordinator.TryDeferClose().Should().BeTrue();
        finishWorkflow.SetResult();
        (await run).Should().BeFalse();

        normalCloseCount.Should().Be(1);
        coordinator.IsActive.Should().BeFalse();
        controls.Should().Equal(false);
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task QueuedEnable_BuildsCommandAfterEarlierFollowOnUpdatesServiceDiscovery()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var factory = new FakeEnableTunnelProcessFactory();
        var enable = new EnableTunnelCoordinator(gate, factory);
        var installedServices = new List<string>();
        var firstStarted = NewCompletion();

        var first = enable.RunAsync(
            () => new ProcessStartInfo
            {
                FileName = "not-launched-by-tests.exe",
                Arguments = string.Join(",", installedServices)
            },
            () => true,
            firstStarted.SetResult,
            _ =>
            {
                installedServices.Add("first");
                return Task.CompletedTask;
            },
            CancellationToken.None);
        await firstStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        var second = enable.RunAsync(
            () => new ProcessStartInfo
            {
                FileName = "not-launched-by-tests.exe",
                Arguments = string.Join(",", installedServices)
            },
            () => true,
            () => { },
            _ => Task.CompletedTask,
            CancellationToken.None);
        factory.Process.Exit();
        await first;
        await second;

        factory.StartArguments.Should().Equal("", "first");
    }

    [Fact]
    public async Task QueuedEnable_ReevaluatesFailedRecoveryAndNeverStartsOrUninstallsServices()
    {
        using var enableGate = new SemaphoreSlim(1, 1);
        using var recoverySoftwareGate = new SemaphoreSlim(1, 1);
        using var recoveryRoutingGate = new SemaphoreSlim(1, 1);
        var recovery = new ConfigCheckStartupRecoveryCoordinator(
            recoverySoftwareGate,
            recoveryRoutingGate);
        var adapter = new FakeStartupRecoveryAdapter();
        await recovery.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            _ => false,
            _ => Task.CompletedTask,
            CancellationToken.None);
        recovery.IsTunnelEnableBlocked.Should().BeFalse("ordinary no-journal startup permits enable");

        await enableGate.WaitAsync();
        var factory = new FakeEnableTunnelProcessFactory();
        var enable = new EnableTunnelCoordinator(enableGate, factory);
        var startInfoCalls = 0;
        var mayStartCalls = 0;
        var run = enable.RunAsync(
            () =>
            {
                startInfoCalls++;
                return new ProcessStartInfo
                {
                    FileName = "not-launched-by-tests.exe",
                    Arguments = "/uninstalltunnelservice retry-identity"
                };
            },
            () =>
            {
                mayStartCalls++;
                return !recovery.IsTunnelEnableBlocked;
            },
            () => { },
            _ => Task.CompletedTask,
            CancellationToken.None);
        mayStartCalls.Should().Be(1);

        adapter.Failure = new IOException("startup recovery failed");
        await Assert.ThrowsAsync<IOException>(() => recovery.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            _ => false,
            _ => Task.CompletedTask,
            CancellationToken.None));
        recovery.IsActive.Should().BeFalse();
        recovery.IsTunnelEnableBlocked.Should().BeTrue();
        enableGate.Release();
        await run;

        mayStartCalls.Should().Be(2, "a queued enable must re-evaluate recovery after the gate wait");
        startInfoCalls.Should().Be(0, "a rejected enable must not even build service mutation commands");
        factory.StartCalls.Should().Be(0);
        factory.StartArguments.Should().NotContain(argument => argument.Contains("uninstalltunnelservice"));
    }

    [Fact]
    public async Task QueuedEnable_SanitizesLatestSourceInsideGateAfterPermissionRecheck()
    {
        var directory = Path.Combine(Path.GetTempPath(), "wgst-enable-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var source = Path.Combine(directory, "selected.conf");
            var derivedDirectory = Path.Combine(directory, "derived");
            var derived = Path.Combine(derivedDirectory, "selected.conf");
            File.WriteAllText(source, "[Peer]\nAllowedIPs = 0.0.0.0/0\nEndpoint = old.example:51820\n");
            Directory.CreateDirectory(derivedDirectory);
            File.WriteAllText(derived, "stale derived contents");

            using var gate = new SemaphoreSlim(1, 1);
            await gate.WaitAsync();
            var factory = new FakeEnableTunnelProcessFactory();
            var enable = new EnableTunnelCoordinator(gate, factory);
            var events = new List<string>();
            var run = enable.RunAsync(
                () =>
                {
                    events.Add("sanitize");
                    gate.CurrentCount.Should().Be(0, "sanitization must run under the routing gate");
                    var installPath = WireguardAllowedIpsSanitizer.EnsureSanitizedConfigFile(
                        source,
                        derivedDirectory);
                    return new ProcessStartInfo
                    {
                        FileName = "not-launched-by-tests.exe",
                        Arguments = installPath
                    };
                },
                () =>
                {
                    events.Add("check");
                    return true;
                },
                () =>
                {
                    events.Add("start");
                    factory.Process.Exit();
                },
                _ =>
                {
                    events.Add("renew");
                    return Task.CompletedTask;
                },
                CancellationToken.None);

            events.Should().Equal("check");
            File.WriteAllText(source, "[Peer]\nAllowedIPs = 0.0.0.0/0\nEndpoint = repaired.example:51820\n");
            gate.Release();
            await run;

            events.Should().Equal("check", "check", "sanitize", "start", "renew");
            factory.StartArguments.Should().Equal(derived);
            factory.StartArguments[0].Should().NotBe(source, "a stale or invalid derived file must never cause source fallback");
            File.ReadAllText(derived).Should().Contain("repaired.example:51820");
            File.ReadAllText(derived).Should().Contain("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1");
            File.ReadAllText(derived).Should().NotContain("stale derived contents");
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Enable_PlaintextSourceReadFailure_NeverStartsProcessOrBuildsServiceMutation()
    {
        var directory = Path.Combine(Path.GetTempPath(), "wgst-enable-read-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var source = Path.Combine(directory, "admin-only.conf");
            File.WriteAllText(source, "[Peer]\nAllowedIPs = 0.0.0.0/0\n");
            using var sourceLock = new FileStream(
                source,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None);
            File.Exists(source).Should().BeTrue("the regression requires an existing but unreadable plaintext source");

            using var gate = new SemaphoreSlim(1, 1);
            var factory = new FakeEnableTunnelProcessFactory();
            var enable = new EnableTunnelCoordinator(gate, factory);
            var serviceMutationCommands = 0;
            var run = enable.RunAsync(
                () =>
                {
                    var installPath = WireguardAllowedIpsSanitizer.EnsureSanitizedConfigFile(
                        source,
                        Path.Combine(directory, "derived"));
                    serviceMutationCommands++;
                    return new ProcessStartInfo
                    {
                        FileName = "not-launched-by-tests.exe",
                        Arguments = $"/uninstalltunnelservice retry-identity & /installtunnelservice \"{installPath}\""
                    };
                },
                () => true,
                factory.Process.Exit,
                _ => Task.CompletedTask,
                CancellationToken.None);

            var actual = await Record.ExceptionAsync(() => run);

            factory.StartCalls.Should().Be(0, "an unreadable plaintext source must fail before process start");
            serviceMutationCommands.Should().Be(0, "service discovery/mutation command construction follows successful sanitation");
            factory.StartArguments.Should().BeEmpty();
            actual.Should().BeOfType<IOException>();
            (await gate.WaitAsync(0)).Should().BeTrue("the failed factory must release the routing gate");
            gate.Release();
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private static TaskCompletionSource NewCompletion() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static ProcessStartInfo UnusedStartInfo() =>
        new() { FileName = "not-launched-by-tests.exe" };

    private sealed class FakeStartupRecoveryAdapter : IConfigCheckRecoveryAdapter
    {
        public Exception? Failure { get; set; }

        public Task<IReadOnlyList<ConfigCheckRecoveredTunnel>> RecoverAllAsync(
            CancellationToken token,
            Func<ConfigCheckRestoreContext, CancellationToken, Task> reconcileDerivedConfigAsync,
            Func<ConfigCheckRecoveredService, CancellationToken, Task>? serviceRestoredAsync = null)
        {
            if (Failure is not null) throw Failure;
            return Task.FromResult<IReadOnlyList<ConfigCheckRecoveredTunnel>>([]);
        }
    }

    private sealed class FakeEnableTunnelProcessFactory : IEnableTunnelProcessFactory
    {
        public FakeEnableTunnelProcess Process { get; } = new();
        public Exception? StartException { get; init; }
        public int StartCalls { get; private set; }
        public List<string> StartArguments { get; } = new();

        public IEnableTunnelProcess Start(ProcessStartInfo startInfo)
        {
            StartCalls++;
            StartArguments.Add(startInfo.Arguments ?? string.Empty);
            if (StartException is not null) throw StartException;
            return Process;
        }
    }

    private sealed class FakeEnableTunnelProcess : IEnableTunnelProcess
    {
        private readonly TaskCompletionSource exited = NewCompletion();

        public int ExitCode { get; }
        public CancellationToken WaitToken { get; private set; }
        public int DisposeCount { get; private set; }

        public Task WaitForExitAsync(CancellationToken cancellationToken)
        {
            WaitToken = cancellationToken;
            return exited.Task;
        }

        public void Exit() => exited.SetResult();

        public void Dispose() => DisposeCount++;
    }
}
