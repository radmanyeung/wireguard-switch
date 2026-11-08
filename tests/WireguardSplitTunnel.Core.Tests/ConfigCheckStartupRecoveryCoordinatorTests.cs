using FluentAssertions;
using WireguardSplitTunnel.Core.ConfigCheck;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ConfigCheckStartupRecoveryCoordinatorTests
{
    [Fact]
    public async Task RunAsync_HoldsSharedGateFromDiscoveryThroughDerivedReconciliationAndApplicableRouteRenewal()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var events = new List<string>();
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(softwareGate, gate);
        var adapter = new FakeRecoveryAdapter
        {
            Recovered = [new ConfigCheckRecoveredTunnel(@"C:\configs\GB.conf", true)],
            RecoverAll = (token, reconcile, serviceRestored) =>
            {
                token.Should().Be(CancellationToken.None);
                gate.CurrentCount.Should().Be(0, "recovery must own the shared routing gate");
                events.Add("discover-and-recover");
                return reconcile(
                    new ConfigCheckRestoreContext(@"C:\configs\GB.conf", @"C:\derived\GB.conf", new string('a', 64)),
                    token);
            }
        };

        await coordinator.RunAsync(
            adapter,
            (context, token) =>
            {
                context.SourcePath.Should().Be(@"C:\configs\GB.conf");
                token.Should().Be(CancellationToken.None);
                gate.CurrentCount.Should().Be(0);
                events.Add("derived-reconciled");
                return Task.CompletedTask;
            },
            service => service.SourcePath == @"C:\configs\GB.conf",
            token =>
            {
                token.Should().Be(CancellationToken.None);
                gate.CurrentCount.Should().Be(0, "route renewal must remain inside the same gate");
                events.Add("routes-renewed");
                return Task.CompletedTask;
            },
            CancellationToken.None);

        events.Should().Equal("discover-and-recover", "derived-reconciled", "routes-renewed");
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task RunAsync_WaitsForSoftwareApplyAndHoldsBothGatesThroughEveryRecoveryStage()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var events = new List<string>();
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(softwareGate, gate);
        var adapter = new FakeRecoveryAdapter
        {
            Recovered = [new ConfigCheckRecoveredTunnel(@"C:\configs\GB.conf", true)],
            RecoverAll = (token, reconcile, serviceRestored) =>
            {
                softwareGate.CurrentCount.Should().Be(0);
                gate.CurrentCount.Should().Be(0);
                events.Add("recovered");
                return reconcile(
                    new ConfigCheckRestoreContext(@"C:\configs\GB.conf", @"C:\derived\GB.conf", new string('a', 64)),
                    token);
            }
        };
        await softwareGate.WaitAsync();

        var run = coordinator.RunAsync(
            adapter,
            (_, _) =>
            {
                softwareGate.CurrentCount.Should().Be(0);
                gate.CurrentCount.Should().Be(0);
                events.Add("derived");
                return Task.CompletedTask;
            },
            _ => true,
            _ =>
            {
                softwareGate.CurrentCount.Should().Be(0);
                gate.CurrentCount.Should().Be(0);
                events.Add("routes");
                return Task.CompletedTask;
            });

        adapter.Attempts.Should().Be(0, "journal recovery must not overlap a software apply");
        gate.CurrentCount.Should().Be(1, "startup recovery must acquire software before routing");
        softwareGate.Release();
        await run;

        events.Should().Equal("recovered", "derived", "routes");
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task RunAsync_NoOriginallyActiveApplicableTunnelSkipsRecoveryRouteRenewal()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(softwareGate, gate);
        var routeRenewals = 0;
        var adapter = new FakeRecoveryAdapter
        {
            Recovered = [new ConfigCheckRecoveredTunnel(@"C:\configs\GB.conf", false)]
        };

        await coordinator.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            _ => true,
            _ =>
            {
                routeRenewals++;
                return Task.CompletedTask;
            },
            CancellationToken.None);

        routeRenewals.Should().Be(0);
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task RunAsync_AmbiguousFailureDoesNotRestoreRoutesAndCanBeRetriedAfterGateRelease()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(softwareGate, gate);
        var failure = new IOException("ambiguous source requires manual review");
        var routeRenewals = 0;
        var adapter = new FakeRecoveryAdapter
        {
            RecoverAll = (_, _, _) => throw failure
        };

        var actual = await Record.ExceptionAsync(() => coordinator.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            _ => true,
            _ =>
            {
                routeRenewals++;
                return Task.CompletedTask;
            },
            CancellationToken.None));

        actual.Should().BeSameAs(failure);
        routeRenewals.Should().Be(0);
        (await gate.WaitAsync(0)).Should().BeTrue("a failed attempt must not deadlock the next startup retry");
        gate.Release();

        adapter.RecoverAll = (_, _, _) => Task.CompletedTask;
        await coordinator.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            _ => false,
            _ => Task.CompletedTask,
            CancellationToken.None);
        adapter.Attempts.Should().Be(2);
    }

    [Fact]
    public async Task RunAsync_ServiceRestoredBeforeLaterRecycleFailureRenewsRoutesImmediatelyAndPreservesFailure()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(softwareGate, gate);
        var recycleFailure = new IOException("later recycle recovery failed");
        var routeRenewals = 0;
        var adapter = new FakeRecoveryAdapter
        {
            RecoverAll = async (_, _, serviceRestored) =>
            {
                serviceRestored.Should().NotBeNull();
                await serviceRestored!(new ConfigCheckRecoveredService(
                    @"C:\configs\GB.conf", "WireGuardTunnel$GB"), CancellationToken.None);
                throw recycleFailure;
            }
        };

        var actual = await Record.ExceptionAsync(() => coordinator.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            service => service.SourcePath == @"C:\configs\GB.conf",
            _ =>
            {
                softwareGate.CurrentCount.Should().Be(0);
                gate.CurrentCount.Should().Be(0);
                routeRenewals++;
                return Task.CompletedTask;
            },
            CancellationToken.None));

        actual.Should().BeSameAs(recycleFailure);
        routeRenewals.Should().Be(1);
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task RunAsync_RouteRenewalFailurePropagatesWithoutSuccessAndReleasesBothGates()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(softwareGate, gate);
        var routeFailure = new IOException("route renewal failed");
        var runCompleted = false;
        var adapter = new FakeRecoveryAdapter
        {
            Recovered = [new ConfigCheckRecoveredTunnel(@"C:\configs\GB.conf", true)]
        };

        var actual = await Record.ExceptionAsync(async () =>
        {
            await coordinator.RunAsync(
                adapter,
                (_, _) => Task.CompletedTask,
                service => service.SourcePath == @"C:\configs\GB.conf",
                _ =>
                {
                    softwareGate.CurrentCount.Should().Be(0);
                    gate.CurrentCount.Should().Be(0);
                    throw routeFailure;
                },
                CancellationToken.None);
            runCompleted = true;
        });

        actual.Should().BeSameAs(routeFailure);
        runCompleted.Should().BeFalse();
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task RunAsync_FailureKeepsEnableBlockedUntilSuccessfulRetry()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(softwareGate, gate);
        var adapter = new FakeRecoveryAdapter
        {
            RecoverAll = (_, _, _) => throw new IOException("recovery failed")
        };

        coordinator.IsTunnelEnableBlocked.Should().BeTrue("pending startup recovery must block enable");
        await Assert.ThrowsAsync<IOException>(() => coordinator.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            _ => false,
            _ => Task.CompletedTask,
            CancellationToken.None));

        coordinator.IsActive.Should().BeFalse();
        coordinator.IsTunnelEnableBlocked.Should().BeTrue(
            "clearing the active flag after a failure must not permit service uninstall or installation");

        adapter.RecoverAll = (_, _, _) => Task.CompletedTask;
        await coordinator.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            _ => false,
            _ => Task.CompletedTask,
            CancellationToken.None);

        coordinator.IsTunnelEnableBlocked.Should().BeFalse(
            "a successful retry, including an ordinary no-journal startup, permits enable");
    }

    [Fact]
    public void PendingStartupFailureBeforeRun_CompletesCloseHandoffWithoutTouchingGates()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var closeCount = 0;
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(
            softwareGate, gate, () =>
            {
                softwareGate.CurrentCount.Should().Be(1);
                gate.CurrentCount.Should().Be(1);
                closeCount++;
            });
        coordinator.TryDeferClose().Should().BeTrue();

        coordinator.CompletePending();
        coordinator.CompletePending();

        closeCount.Should().Be(1);
        coordinator.IsActive.Should().BeFalse();
        coordinator.CloseWasRequested.Should().BeTrue();
        coordinator.TryDeferClose().Should().BeFalse();
    }

    [Fact]
    public async Task CloseBeforeRun_JoinsPendingRecoveryAndIgnoresCloseCancellation()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        using var closeCancellation = new CancellationTokenSource();
        var closeCount = 0;
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(
            softwareGate, gate, () => closeCount++);
        var adapter = new FakeRecoveryAdapter();

        coordinator.IsActive.Should().BeTrue("startup recovery is pending before its first async yield");
        coordinator.TryDeferClose().Should().BeTrue();
        coordinator.TryDeferClose().Should().BeTrue("repeated close requests join the same handoff");
        closeCancellation.Cancel();
        closeCount.Should().Be(0);

        await coordinator.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            _ => false,
            _ => Task.CompletedTask,
            closeCancellation.Token);

        adapter.Attempts.Should().Be(1, "close cancellation must not abandon startup recovery");
        closeCount.Should().Be(1);
        coordinator.IsActive.Should().BeFalse();
        coordinator.CloseWasRequested.Should().BeTrue();
        coordinator.TryDeferClose().Should().BeFalse("the resumed normal close must be allowed to proceed");
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task CloseDuringServiceRecovery_DoesNotResumeUntilRecoveryAndGateCleanupFinish()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var recoveryStarted = AsyncSignal();
        var finishRecovery = AsyncSignal();
        var closeCount = 0;
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(
            softwareGate, gate, () =>
            {
                softwareGate.CurrentCount.Should().Be(1, "software gate must be released before close resumes");
                gate.CurrentCount.Should().Be(1, "routing gate must be released before close resumes");
                closeCount++;
            });
        var adapter = new FakeRecoveryAdapter
        {
            RecoverAll = async (_, _, _) =>
            {
                recoveryStarted.SetResult();
                await finishRecovery.Task;
            }
        };
        var run = coordinator.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            _ => false,
            _ => Task.CompletedTask,
            CancellationToken.None);
        await recoveryStarted.Task;

        coordinator.TryDeferClose().Should().BeTrue();
        coordinator.TryDeferClose().Should().BeTrue();
        closeCount.Should().Be(0);
        run.IsCompleted.Should().BeFalse();

        finishRecovery.SetResult();
        await run;

        closeCount.Should().Be(1);
        coordinator.IsActive.Should().BeFalse();
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task CloseDuringRouteRenewal_DefersCloseWithoutRenewingRoutesAgain()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var routeStarted = AsyncSignal();
        var finishRoute = AsyncSignal();
        var closeCount = 0;
        var routeRenewals = 0;
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(
            softwareGate, gate, () => closeCount++);
        var adapter = new FakeRecoveryAdapter
        {
            Recovered = [new ConfigCheckRecoveredTunnel(@"C:\configs\GB.conf", true)]
        };
        var run = coordinator.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            _ => true,
            async _ =>
            {
                routeRenewals++;
                routeStarted.SetResult();
                await finishRoute.Task;
            },
            CancellationToken.None);
        await routeStarted.Task;

        coordinator.TryDeferClose().Should().BeTrue();
        coordinator.TryDeferClose().Should().BeTrue();
        closeCount.Should().Be(0);
        routeRenewals.Should().Be(1);
        gate.CurrentCount.Should().Be(0, "the route callback still owns the routing gate");

        finishRoute.SetResult();
        await run;

        closeCount.Should().Be(1);
        routeRenewals.Should().Be(1, "resuming close must not repeat incremental route restoration");
        coordinator.IsActive.Should().BeFalse();
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task CloseDuringFailureCleanup_ResumesOnlyAfterFailureAndGateRelease()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var recoveryStarted = AsyncSignal();
        var failRecovery = AsyncSignal();
        var failure = new IOException("recovery failed");
        var closeCount = 0;
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(
            softwareGate, gate, () =>
            {
                softwareGate.CurrentCount.Should().Be(1);
                gate.CurrentCount.Should().Be(1);
                closeCount++;
            });
        var adapter = new FakeRecoveryAdapter
        {
            RecoverAll = async (_, _, _) =>
            {
                recoveryStarted.SetResult();
                await failRecovery.Task;
                throw failure;
            }
        };
        var run = coordinator.RunAsync(
            adapter,
            (_, _) => Task.CompletedTask,
            _ => false,
            _ => Task.CompletedTask,
            CancellationToken.None);
        await recoveryStarted.Task;

        coordinator.TryDeferClose().Should().BeTrue();
        closeCount.Should().Be(0);
        failRecovery.SetResult();
        var actual = await Record.ExceptionAsync(() => run);

        actual.Should().BeSameAs(failure);
        closeCount.Should().Be(1);
        coordinator.IsActive.Should().BeFalse();
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task OrdinaryCloseAfterRecovery_IsNotDeferredOrResumedByCoordinator()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var closeCount = 0;
        var coordinator = new ConfigCheckStartupRecoveryCoordinator(
            softwareGate, gate, () => closeCount++);

        await coordinator.RunAsync(
            new FakeRecoveryAdapter(),
            (_, _) => Task.CompletedTask,
            _ => false,
            _ => Task.CompletedTask,
            CancellationToken.None);

        coordinator.IsActive.Should().BeFalse();
        coordinator.CloseWasRequested.Should().BeFalse();
        coordinator.TryDeferClose().Should().BeFalse();
        closeCount.Should().Be(0);
    }

    private static TaskCompletionSource AsyncSignal() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private sealed class FakeRecoveryAdapter : IConfigCheckRecoveryAdapter
    {
        public IReadOnlyList<ConfigCheckRecoveredTunnel> Recovered { get; init; } = [];
        public Func<CancellationToken, Func<ConfigCheckRestoreContext, CancellationToken, Task>, Func<ConfigCheckRecoveredService, CancellationToken, Task>?, Task>? RecoverAll { get; set; }
        public int Attempts { get; private set; }

        public async Task<IReadOnlyList<ConfigCheckRecoveredTunnel>> RecoverAllAsync(
            CancellationToken token,
            Func<ConfigCheckRestoreContext, CancellationToken, Task> reconcileDerivedConfigAsync,
            Func<ConfigCheckRecoveredService, CancellationToken, Task>? serviceRestoredAsync = null)
        {
            Attempts++;
            if (RecoverAll is not null) await RecoverAll(token, reconcileDerivedConfigAsync, serviceRestoredAsync);
            if (serviceRestoredAsync is not null)
            {
                foreach (var item in Recovered.Where(item => item.OriginalServiceWasRunning))
                {
                    await serviceRestoredAsync(
                        new ConfigCheckRecoveredService(
                            item.SourcePath,
                            "WireGuardTunnel$" + global::WireguardSplitTunnel.Core.Services.WireguardConfigCatalog.GetTunnelName(item.SourcePath)),
                        CancellationToken.None);
                }
            }
            return Recovered;
        }
    }
}
