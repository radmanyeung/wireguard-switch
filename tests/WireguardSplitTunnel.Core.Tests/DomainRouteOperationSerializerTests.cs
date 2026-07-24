using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class DomainRouteOperationSerializerTests
{
    [Fact]
    public async Task RunAsync_WhenRouteOperationOwnsGate_QueuesMutationUntilRelease()
    {
        using var gate = new SemaphoreSlim(1, 1);
        await gate.WaitAsync();
        var mutationRan = false;

        var mutationTask = DomainRouteOperationSerializer.RunAsync(
            gate,
            () => mutationRan = true);

        mutationTask.IsCompleted.Should().BeFalse();
        mutationRan.Should().BeFalse();

        gate.Release();
        await mutationTask;

        mutationRan.Should().BeTrue();
    }

    [Fact]
    public async Task RunAsync_WhenMutationThrows_ReleasesGate()
    {
        using var gate = new SemaphoreSlim(1, 1);

        Func<Task> action = () => DomainRouteOperationSerializer.RunAsync(
            gate,
            () => throw new InvalidOperationException("mutation failed"));

        await action.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("mutation failed");

        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task RunAsync_WhileIncrementalRouteCallbackIsInFlight_WaitsUntilSnapshotCommit()
    {
        using var gate = new SemaphoreSlim(1, 1);
        var state = new AppState(
            [new DomainRule("*.claude.ai")],
            new Dictionary<string, List<string>>(),
            []);
        var reconciler = new IncrementalDnsRouteReconciler(
            new FakeDnsCacheReader(
                [new DnsCacheEntry("downloads.claude.ai", "198.51.100.25")]));
        var routeCallbackStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var allowRouteCallbackToComplete = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var reconcileTask = RunReconcileUnderGateAsync();
        await routeCallbackStarted.Task;

        var mutationTask = DomainRouteOperationSerializer.RunAsync(gate, () =>
            RuleStateMutations.TrySetRuleEnabled(state, "*.claude.ai", false));

        mutationTask.IsCompleted.Should().BeFalse();
        state.DomainRules.Single().Enabled.Should().BeTrue();
        state.ManagedRouteSnapshot.Should().BeEmpty();

        allowRouteCallbackToComplete.SetResult();
        await reconcileTask;

        state.ManagedRouteSnapshot.Should().ContainSingle()
            .Which.Should().Be(new ManagedRouteEntry("*.claude.ai", "198.51.100.25"));

        await mutationTask;
        state.DomainRules.Single().Enabled.Should().BeFalse();

        async Task RunReconcileUnderGateAsync()
        {
            await gate.WaitAsync();
            try
            {
                await reconciler.ReconcileAsync(
                    state,
                    async (_, _) =>
                    {
                        routeCallbackStarted.SetResult();
                        await allowRouteCallbackToComplete.Task;
                    },
                    CancellationToken.None);
            }
            finally
            {
                gate.Release();
            }
        }
    }

    [Fact]
    public async Task RunAsync_WhileIncrementalRouteCallbackIsInFlight_AsyncRestoreSeesCommittedRoute()
    {
        using var gate = new SemaphoreSlim(1, 1);
        var state = new AppState(
            [new DomainRule("*.claude.ai")],
            new Dictionary<string, List<string>>(),
            []);
        var reconciler = new IncrementalDnsRouteReconciler(
            new FakeDnsCacheReader(
                [new DnsCacheEntry("downloads.claude.ai", "198.51.100.25")]));
        var routeCallbackStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var allowRouteCallbackToComplete = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var restoreStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var allowRestoreToComplete = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var restoredIps = new List<string>();

        var reconcileTask = RunReconcileUnderGateAsync();
        await routeCallbackStarted.Task;

        Func<Task> restoreOperation = async () =>
        {
            restoreStarted.SetResult();
            await allowRestoreToComplete.Task;
            restoredIps.AddRange(
                state.ManagedRouteSnapshot.Select(entry => entry.IpAddress));
            state.ManagedRouteSnapshot.Clear();
        };
        var restoreTask = DomainRouteOperationSerializer.RunAsync(gate, restoreOperation);

        restoreTask.IsCompleted.Should().BeFalse();
        restoredIps.Should().BeEmpty();

        allowRouteCallbackToComplete.SetResult();
        await reconcileTask;
        await restoreStarted.Task;

        restoreTask.IsCompleted.Should().BeFalse();
        restoredIps.Should().BeEmpty();

        allowRestoreToComplete.SetResult();
        await restoreTask;

        restoredIps.Should().Equal("198.51.100.25");
        state.ManagedRouteSnapshot.Should().BeEmpty();

        async Task RunReconcileUnderGateAsync()
        {
            await gate.WaitAsync();
            try
            {
                await reconciler.ReconcileAsync(
                    state,
                    async (_, _) =>
                    {
                        routeCallbackStarted.SetResult();
                        await allowRouteCallbackToComplete.Task;
                    },
                    CancellationToken.None);
            }
            finally
            {
                gate.Release();
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