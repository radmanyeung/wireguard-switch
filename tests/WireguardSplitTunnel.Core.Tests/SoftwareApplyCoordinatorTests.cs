using FluentAssertions;
using WireguardSplitTunnel.Core.ConfigCheck;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class SoftwareApplyCoordinatorTests
{
    [Fact]
    public async Task QueuedApply_RechecksGuardAndDoesNotRunWhenConfigCheckBecameActive()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var routingGate = new SemaphoreSlim(1, 1);
        using var allowSecondGuardCheck = new ManualResetEventSlim();
        var software = new SoftwareApplyCoordinator(softwareGate);
        var config = new ConfigCheckCoordinator(softwareGate, routingGate, () => { });
        var initialGuardChecked = NewCompletion();
        var secondGuardCheckEntered = NewCompletion();
        var workflowStarted = NewCompletion();
        var finishWorkflow = NewCompletion();
        var guardChecks = 0;
        var applyCount = 0;

        await softwareGate.WaitAsync();
        var queuedApply = software.RunAsync(
            () =>
            {
                guardChecks++;
                if (guardChecks == 1)
                {
                    initialGuardChecked.SetResult();
                }
                else
                {
                    secondGuardCheckEntered.SetResult();
                    allowSecondGuardCheck.Wait(TimeSpan.FromSeconds(2)).Should().BeTrue(
                        "the test must explicitly activate config checking before the second guard completes");
                }

                return !config.IsActive;
            },
            _ =>
            {
                applyCount++;
                return Task.CompletedTask;
            });
        await initialGuardChecked.Task.WaitAsync(TimeSpan.FromSeconds(2));
        softwareGate.Release();
        await secondGuardCheckEntered.Task.WaitAsync(TimeSpan.FromSeconds(2));

        // The queued apply now owns the software gate inside its second guard.
        // Starting config check here makes the interleaving deterministic without
        // relying on SemaphoreSlim waiter wake-up ordering.
        var configRun = config.RunAsync(
            _ => Task.FromResult(true),
            async _ =>
            {
                softwareGate.CurrentCount.Should().Be(0);
                routingGate.CurrentCount.Should().Be(0);
                workflowStarted.SetResult();
                await finishWorkflow.Task;
            },
            _ => Task.CompletedTask,
            _ => { });
        config.IsActive.Should().BeTrue();
        allowSecondGuardCheck.Set();

        (await queuedApply).Should().BeFalse();
        await workflowStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        guardChecks.Should().Be(2);
        applyCount.Should().Be(0, "a queued apply must not run inside config checking or restoration");
        softwareGate.CurrentCount.Should().Be(0);
        routingGate.CurrentCount.Should().Be(0);

        finishWorkflow.SetResult();
        (await configRun).Should().BeTrue();
        (await software.RunAsync(() => !config.IsActive, _ =>
        {
            applyCount++;
            softwareGate.CurrentCount.Should().Be(0);
            return Task.CompletedTask;
        })).Should().BeTrue();
        applyCount.Should().Be(1);
    }

    [Fact]
    public async Task RejectedAndCanceledAttempts_DoNotLeakSoftwareGate()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var cancellation = new CancellationTokenSource();
        var software = new SoftwareApplyCoordinator(softwareGate);
        var applyCount = 0;

        await softwareGate.WaitAsync();
        var queued = software.RunAsync(
            () => true,
            _ =>
            {
                applyCount++;
                return Task.CompletedTask;
            },
            cancellation.Token);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued);
        softwareGate.CurrentCount.Should().Be(0, "the test blocker must remain owned by the caller");
        softwareGate.Release();

        (await software.RunAsync(() => false, _ =>
        {
            applyCount++;
            return Task.CompletedTask;
        })).Should().BeFalse();
        (await software.RunAsync(() => true, _ =>
        {
            applyCount++;
            softwareGate.CurrentCount.Should().Be(0);
            return Task.CompletedTask;
        })).Should().BeTrue();

        applyCount.Should().Be(1);
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
    }

    [Fact]
    public async Task ApplyFailure_ReleasesGateForConfigCheckAndLaterApply()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var routingGate = new SemaphoreSlim(1, 1);
        var software = new SoftwareApplyCoordinator(softwareGate);
        var failure = new InvalidOperationException("apply failed");

        var actual = await Record.ExceptionAsync(() => software.RunAsync(
            () => true,
            _ => throw failure));
        actual.Should().BeSameAs(failure);
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();

        var config = new ConfigCheckCoordinator(softwareGate, routingGate, () => { });
        (await config.RunAsync(
            _ => Task.FromResult(true),
            _ =>
            {
                softwareGate.CurrentCount.Should().Be(0);
                routingGate.CurrentCount.Should().Be(0);
                return Task.CompletedTask;
            },
            _ => Task.CompletedTask,
            _ => { })).Should().BeTrue();
        (await software.RunAsync(() => true, _ => Task.CompletedTask)).Should().BeTrue();
    }

    private static TaskCompletionSource NewCompletion() =>
        new(TaskCreationOptions.RunContinuationsAsynchronously);
}
