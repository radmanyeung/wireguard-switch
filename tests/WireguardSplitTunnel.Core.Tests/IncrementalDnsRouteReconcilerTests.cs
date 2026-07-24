using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class IncrementalDnsRouteReconcilerTests
{
    [Fact]
    public async Task ReconcileAsync_AddsLearnedIpv4BeforeUpdatingState()
    {
        var state = CreateState(new DomainRule("*.openai.com"));
        var reconciler = new IncrementalDnsRouteReconciler(new FakeDnsCacheReader(
        [
            new DnsCacheEntry("auth.openai.com", "198.51.100.10"),
            new DnsCacheEntry("cdn.openai.com", "198.51.100.11")
        ]));
        IReadOnlyCollection<string>? added = null;

        var result = await reconciler.ReconcileAsync(
            state,
            (ips, _) =>
            {
                state.ManagedRouteSnapshot.Should().BeEmpty();
                state.LastKnownResolvedIps.Should().BeEmpty();
                added = ips;
                return Task.CompletedTask;
            },
            CancellationToken.None);

        result.Should().Be(new IncrementalDnsRouteReconcileResult(2, 2, true));
        added.Should().Equal("198.51.100.10", "198.51.100.11");
        state.ManagedRouteSnapshot.Should().Equal(
            new ManagedRouteEntry("*.openai.com", "198.51.100.10"),
            new ManagedRouteEntry("*.openai.com", "198.51.100.11"));
        state.LastKnownResolvedIps["*.openai.com"].Should().Equal("198.51.100.10", "198.51.100.11");
    }

    [Fact]
    public async Task ReconcileAsync_WithUnchangedCache_DoesNotInvokeCallbackOrChangeState()
    {
        var state = CreateState(new DomainRule("*.openai.com"));
        var reconciler = new IncrementalDnsRouteReconciler(new FakeDnsCacheReader(
            [new DnsCacheEntry("auth.openai.com", "198.51.100.10")]));
        var calls = 0;

        await reconciler.ReconcileAsync(state, (_, _) =>
        {
            calls++;
            return Task.CompletedTask;
        }, CancellationToken.None);
        var result = await reconciler.ReconcileAsync(state, (_, _) =>
        {
            calls++;
            return Task.CompletedTask;
        }, CancellationToken.None);

        result.Should().Be(new IncrementalDnsRouteReconcileResult(1, 0, false));
        calls.Should().Be(1);
    }

    [Fact]
    public async Task ReconcileAsync_WhenRouteApplyFails_LeavesStateUntouched()
    {
        var state = CreateState(new DomainRule("*.openai.com"));
        state.ManagedRouteSnapshot.Add(new ManagedRouteEntry("old.example.com", "203.0.113.10"));
        state.LastKnownResolvedIps["old.example.com"] = ["203.0.113.10"];
        state.LastKnownResolvedIpDetails["old.example.com"] =
            [new ResolvedIpDetail("203.0.113.10", "old.example.com", ResolvedIpSourceKind.Direct)];
        var reconciler = new IncrementalDnsRouteReconciler(new FakeDnsCacheReader(
            [new DnsCacheEntry("auth.openai.com", "198.51.100.10")]));

        Func<Task> action = () => reconciler.ReconcileAsync(
            state,
            (_, _) => Task.FromException(new InvalidOperationException("route failed")),
            CancellationToken.None);

        await action.Should().ThrowAsync<InvalidOperationException>().WithMessage("route failed");
        state.ManagedRouteSnapshot.Should().Equal(new ManagedRouteEntry("old.example.com", "203.0.113.10"));
        state.LastKnownResolvedIps.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(new KeyValuePair<string, List<string>>("old.example.com", ["203.0.113.10"]));
        state.LastKnownResolvedIpDetails.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(new KeyValuePair<string, List<ResolvedIpDetail>>(
                "old.example.com",
                [new ResolvedIpDetail("203.0.113.10", "old.example.com", ResolvedIpSourceKind.Direct)]));
    }

    [Fact]
    public async Task ReconcileAsync_IgnoresInvalidIpv6RootDisabledBypassAndExactCacheMatches()
    {
        var state = CreateState(
            new DomainRule("*.openai.com"),
            new DomainRule("*.disabled.example.com", false),
            new DomainRule("*.bypass.example.com", true, DomainRouteMode.BypassWireGuard),
            new DomainRule("exact.example.com"));
        var reconciler = new IncrementalDnsRouteReconciler(new FakeDnsCacheReader(
        [
            new DnsCacheEntry("openai.com", "198.51.100.10"),
            new DnsCacheEntry("chat.openai.com", "2001:db8::1"),
            new DnsCacheEntry("bad.openai.com", "not-an-ip"),
            new DnsCacheEntry("cdn.disabled.example.com", "198.51.100.11"),
            new DnsCacheEntry("cdn.bypass.example.com", "198.51.100.12"),
            new DnsCacheEntry("exact.example.com", "198.51.100.13")
        ]));
        var calls = 0;

        var result = await reconciler.ReconcileAsync(state, (_, _) =>
        {
            calls++;
            return Task.CompletedTask;
        }, CancellationToken.None);

        result.Should().Be(new IncrementalDnsRouteReconcileResult(0, 0, false));
        calls.Should().Be(0);
        state.ManagedRouteSnapshot.Should().BeEmpty();
        state.LastKnownResolvedIps.Should().BeEmpty();
    }

    [Fact]
    public async Task ReconcileAsync_WithPreCancelledToken_DoesNotReadCacheOrMutateState()
    {
        var reader = new CountingDnsCacheReader([new DnsCacheEntry("auth.openai.com", "198.51.100.10")]);
        var reconciler = new IncrementalDnsRouteReconciler(reader);
        var state = CreateState(new DomainRule("*.openai.com"));
        using var cancellationSource = new CancellationTokenSource();
        cancellationSource.Cancel();
        var callbackCalls = 0;

        Func<Task> action = () => reconciler.ReconcileAsync(state, (_, _) =>
        {
            callbackCalls++;
            return Task.CompletedTask;
        }, cancellationSource.Token);

        await action.Should().ThrowAsync<OperationCanceledException>();
        reader.ReadCount.Should().Be(0);
        callbackCalls.Should().Be(0);
        state.ManagedRouteSnapshot.Should().BeEmpty();
        state.LastKnownResolvedIps.Should().BeEmpty();
    }

    [Fact]
    public async Task ReconcileAsync_WhenDnsReaderThrows_PropagatesWithoutCallbackOrStateMutation()
    {
        var reconciler = new IncrementalDnsRouteReconciler(new ThrowingDnsCacheReader());
        var state = CreateState(new DomainRule("*.openai.com"));
        var callbackCalls = 0;

        Func<Task> action = () => reconciler.ReconcileAsync(state, (_, _) =>
        {
            callbackCalls++;
            return Task.CompletedTask;
        }, CancellationToken.None);

        await action.Should().ThrowAsync<InvalidOperationException>().WithMessage("dns failed");
        callbackCalls.Should().Be(0);
        state.ManagedRouteSnapshot.Should().BeEmpty();
        state.LastKnownResolvedIps.Should().BeEmpty();
    }

    [Fact]
    public async Task ReconcileAsync_WithSharedIpAcrossOverlappingWildcards_CountsAndAddsItOnce()
    {
        var state = CreateState(new DomainRule("*.openai.com"), new DomainRule("*.api.openai.com"));
        var reconciler = new IncrementalDnsRouteReconciler(new FakeDnsCacheReader(
            [new DnsCacheEntry("auth.api.openai.com", "198.51.100.10")]));
        IReadOnlyCollection<string>? added = null;

        var result = await reconciler.ReconcileAsync(state, (ips, _) =>
        {
            added = ips;
            return Task.CompletedTask;
        }, CancellationToken.None);

        result.Should().Be(new IncrementalDnsRouteReconcileResult(1, 1, true));
        added.Should().Equal("198.51.100.10");
        state.ManagedRouteSnapshot.Should().ContainSingle();
    }

    [Fact]
    public async Task ReconcileAsync_WhenReaderCancelsAfterReturningUnchangedRoute_ThrowsWithoutCallbackOrStateMutation()
    {
        using var cancellationSource = new CancellationTokenSource();
        var state = CreateState(new DomainRule("*.openai.com"));
        state.ManagedRouteSnapshot.Add(new ManagedRouteEntry("*.openai.com", "198.51.100.10"));
        var reconciler = new IncrementalDnsRouteReconciler(new CancellingDnsCacheReader(
            cancellationSource,
            [new DnsCacheEntry("auth.openai.com", "198.51.100.10")]));
        var callbackCalls = 0;

        Func<Task> action = () => reconciler.ReconcileAsync(state, (_, _) =>
        {
            callbackCalls++;
            return Task.CompletedTask;
        }, cancellationSource.Token);

        await action.Should().ThrowAsync<OperationCanceledException>();
        callbackCalls.Should().Be(0);
        state.ManagedRouteSnapshot.Should().Equal(new ManagedRouteEntry("*.openai.com", "198.51.100.10"));
        state.LastKnownResolvedIps.Should().BeEmpty();
        state.LastKnownResolvedIpDetails.Should().BeEmpty();
    }
    private static AppState CreateState(params DomainRule[] rules) =>
        new(rules.ToList(), new Dictionary<string, List<string>>(), []);

    private sealed class FakeDnsCacheReader(IReadOnlyCollection<DnsCacheEntry> entries) : IDnsCacheReader
    {
        public Task<IReadOnlyCollection<DnsCacheEntry>> ReadAsync(CancellationToken cancellationToken) =>
            Task.FromResult(entries);
    }

    private sealed class CountingDnsCacheReader(IReadOnlyCollection<DnsCacheEntry> entries) : IDnsCacheReader
    {
        public int ReadCount { get; private set; }

        public Task<IReadOnlyCollection<DnsCacheEntry>> ReadAsync(CancellationToken cancellationToken)
        {
            ReadCount++;
            return Task.FromResult(entries);
        }
    }

    private sealed class ThrowingDnsCacheReader : IDnsCacheReader
    {
        public Task<IReadOnlyCollection<DnsCacheEntry>> ReadAsync(CancellationToken cancellationToken) =>
            Task.FromException<IReadOnlyCollection<DnsCacheEntry>>(new InvalidOperationException("dns failed"));
    }
    private sealed class CancellingDnsCacheReader(
        CancellationTokenSource cancellationSource,
        IReadOnlyCollection<DnsCacheEntry> entries) : IDnsCacheReader
    {
        public Task<IReadOnlyCollection<DnsCacheEntry>> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationSource.Cancel();
            return Task.FromResult(entries);
        }
    }
}