using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class RuleResolutionCoordinatorTests
{
    [Fact]
    public async Task ResolveEnabledRulesAsync_CloseCancellation_ReleasesRoutingGateEvenIfResolverIsStuck()
    {
        using var gate = new SemaphoreSlim(1, 1);
        using var closing = new CancellationTokenSource();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resolver = new BlockingDomainResolver(started);
        var coordinator = new RuleResolutionCoordinator(resolver);
        var renewal = DomainRouteOperationSerializer.RunAsync(gate,
            () => coordinator.ResolveEnabledRulesAsync([new DomainRule("slow.example.com")], closing.Token),
            closing.Token);
        await started.Task;

        closing.Cancel();
        Func<Task> cancelled = () => renewal.WaitAsync(TimeSpan.FromSeconds(1));
        await cancelled.Should().ThrowAsync<OperationCanceledException>();
        var restored = false;
        await DomainRouteOperationSerializer.RunAsync(gate, () => restored = true)
            .WaitAsync(TimeSpan.FromSeconds(1));
        restored.Should().BeTrue("normal close must acquire the gate and restore the bypass routes");
    }

    private sealed class BlockingDomainResolver(TaskCompletionSource started) : IDomainResolver
    {
        public Task<IReadOnlyCollection<string>> ResolveAsync(string domain, CancellationToken cancellationToken)
        {
            started.TrySetResult();
            return new TaskCompletionSource<IReadOnlyCollection<string>>().Task;
        }
    }

    [Fact]
    public async Task ResolveEnabledRulesAsync_ReturnsResultsPerEnabledRule()
    {
        var resolver = new FakeDomainResolver();
        var coordinator = new RuleResolutionCoordinator(resolver);
        var rules = new[]
        {
            new DomainRule("enabled-one.example.com", true),
            new DomainRule("disabled.example.com", false),
            new DomainRule("enabled-two.example.com", true)
        };

        var results = await coordinator.ResolveEnabledRulesAsync(rules, CancellationToken.None);

        results.Should().HaveCount(2);
        results.Select(result => result.Rule.Domain).Should().Equal(
            "enabled-one.example.com",
            "enabled-two.example.com");
        results.SelectMany(result => result.ResolvedIps).Should().Contain(
            "203.0.113.10",
            "203.0.113.20");
        resolver.ResolvedDomains.Should().Equal(
            "enabled-one.example.com",
            "enabled-two.example.com");
    }

    [Fact]
    public async Task ResolveEnabledRulesAsync_SkipsRule_WhenResolverThrows()
    {
        var resolver = new FakeDomainResolver();
        var coordinator = new RuleResolutionCoordinator(resolver);
        var rules = new[]
        {
            new DomainRule("enabled-one.example.com", true),
            new DomainRule("boom.example.com", true),
            new DomainRule("enabled-two.example.com", true)
        };

        var results = await coordinator.ResolveEnabledRulesAsync(rules, CancellationToken.None);

        results.Select(result => result.Rule.Domain).Should().Equal(
            "enabled-one.example.com",
            "enabled-two.example.com");
    }

    private sealed class FakeDomainResolver : IDomainResolver
    {
        public List<string> ResolvedDomains { get; } = [];

        public Task<IReadOnlyCollection<string>> ResolveAsync(string domain, CancellationToken cancellationToken)
        {
            ResolvedDomains.Add(domain);

            if (domain == "boom.example.com")
            {
                throw new InvalidOperationException("Simulated resolver failure");
            }

            IReadOnlyCollection<string> resolvedIps = domain switch
            {
                "enabled-one.example.com" => ["203.0.113.10"],
                "enabled-two.example.com" => ["203.0.113.20"],
                _ => []
            };

            return Task.FromResult(resolvedIps);
        }
    }
}
