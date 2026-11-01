using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class BypassRouteLeaseServiceTests
{
    private static readonly BypassRouteKey[] Pair =
    [
        new("0.0.0.0", 1, 27, "normal-adapter", "192.168.68.253"),
        new("128.0.0.0", 1, 27, "normal-adapter", "192.168.68.253")
    ];

    [Fact]
    public void Close_RemovesBothAppCreatedHalves_AndKeepsUnrelatedRoutes()
    {
        var table = new MemoryRoutes();
        var vpn = Pair[0] with { InterfaceIndex = 83, InterfaceId = "vpn", Gateway = "0.0.0.0" };
        table.Rows[vpn] = 35;
        var otherGateway = Pair[0] with { Gateway = "192.168.68.254" };
        table.Rows[otherGateway] = 4;
        var service = new BypassRouteLeaseService(table);
        var changes = new List<BypassRouteChange>();
        service.EnsureHalfDefaults(Pair, changes, () => { }, false);

        service.Restore(changes, () => { }, CancellationToken.None).Should().Be(2);

        Pair.Should().OnlyContain(r => !table.Rows.ContainsKey(r));
        table.Rows.Should().Contain(vpn, 35).And.Contain(otherGateway, 4);
        changes.Should().BeEmpty();
    }

    [Fact]
    public void RepeatedApply_RestoresTheOriginalDefaultMetric()
    {
        var route = Pair[0] with { PrefixLength = 0 };
        var table = new MemoryRoutes();
        table.Rows[route] = 25;
        var service = new BypassRouteLeaseService(table);
        var changes = new List<BypassRouteChange>();
        service.EnsureDefault(route, changes, () => { });
        service.EnsureDefault(route, changes, () => { });
        changes.Should().ContainSingle().Which.PreviousMetric.Should().Be(25);

        service.Restore(changes, () => { }, CancellationToken.None);

        table.Rows[route].Should().Be(25);
    }

    [Fact]
    public void Close_RestoresPreexistingHalfRoutesInsteadOfDeletingThem()
    {
        var table = new MemoryRoutes();
        foreach (var route in Pair) table.Rows[route] = 60;
        var service = new BypassRouteLeaseService(table);
        var changes = new List<BypassRouteChange>();
        service.EnsureHalfDefaults(Pair, changes, () => { }, true);

        service.Restore(changes, () => { }, CancellationToken.None);

        Pair.Should().OnlyContain(r => table.Rows[r] == 60);
    }

    [Fact]
    public void Close_DoesNotOverwriteARouteChangedByAnotherOwner()
    {
        var table = new MemoryRoutes();
        var service = new BypassRouteLeaseService(table);
        var changes = new List<BypassRouteChange>();
        service.EnsureHalfDefaults(Pair, changes, () => { }, false);
        table.Rows[Pair[0]] = 99;

        service.Restore(changes, () => { }, CancellationToken.None);

        table.Rows[Pair[0]].Should().Be(99);
        table.Rows.Should().NotContainKey(Pair[1]);
    }

    [Fact]
    public void Close_HandlesAnAbsentAdapterWithoutTouchingAReusedIndex()
    {
        var table = new MemoryRoutes();
        var changes = new List<BypassRouteChange> { new(Pair[0], 5, null) };
        var reused = Pair[0] with { InterfaceId = "new-adapter" };
        table.Rows[reused] = 5;

        new BypassRouteLeaseService(table).Restore(changes, () => { }, CancellationToken.None);

        table.Rows.Should().Contain(reused, 5);
        changes.Should().BeEmpty();
    }

    [Fact]
    public void Restore_FailedDeleteRetainsDebt_AndStillCleansTheOtherHalf()
    {
        var table = new MemoryRoutes();
        var service = new BypassRouteLeaseService(table);
        var changes = new List<BypassRouteChange>();
        service.EnsureHalfDefaults(Pair, changes, () => { }, false);
        table.FailDelete = Pair[0];

        Action restore = () => service.Restore(changes, () => { }, CancellationToken.None);
        restore.Should().Throw<InvalidOperationException>();

        changes.Should().ContainSingle().Which.Route.Should().Be(Pair[0]);
        table.Rows.Should().NotContainKey(Pair[1]);
        table.FailDelete = null;
        service.Restore(changes, () => { }, CancellationToken.None);
        changes.Should().BeEmpty();
    }

    [Fact]
    public void Apply_RecordsCleanupBeforeTheFirstMutation()
    {
        var table = new MemoryRoutes();
        var changes = new List<BypassRouteChange>();
        var persisted = new List<BypassRouteChange>();
        table.BeforeWrite = r => persisted.Should().Contain(c => c.Route == r);

        new BypassRouteLeaseService(table).EnsureHalfDefaults(Pair, changes,
            () => persisted = changes.ToList(), false);
    }

    [Fact]
    public void Apply_WhenSavingFails_DoesNotChangeTheRoute()
    {
        var table = new MemoryRoutes();
        Action apply = () => new BypassRouteLeaseService(table).EnsureHalfDefaults(
            Pair, [], () => throw new IOException("disk full"), false);

        apply.Should().Throw<IOException>();
        table.Rows.Should().BeEmpty();
    }

    [Fact]
    public void Apply_AfterASaveFailure_PersistsTheInMemoryDebtBeforeRetrying()
    {
        var table = new MemoryRoutes();
        var changes = new List<BypassRouteChange>();
        var service = new BypassRouteLeaseService(table);
        Action first = () => service.EnsureHalfDefaults(Pair, changes,
            () => throw new IOException("disk full"), false);
        first.Should().Throw<IOException>();
        var persisted = new List<BypassRouteChange>();
        table.BeforeWrite = r => persisted.Should().Contain(c => c.Route == r);

        service.EnsureHalfDefaults(Pair, changes, () => persisted = changes.ToList(), false);

        persisted.Should().HaveCount(2);
    }

    [Fact]
    public void LegacyPair_IsAdoptedOnlyAsACompleteMetricFivePair()
    {
        var table = new MemoryRoutes();
        foreach (var route in Pair) table.Rows[route] = 5;
        var changes = new List<BypassRouteChange>();
        var service = new BypassRouteLeaseService(table);
        service.AdoptLegacyPair(Pair, changes, () => { }, true);
        changes.Should().HaveCount(2).And.OnlyContain(c => c.PreviousMetric == null);

        service.Restore(changes, () => { }, CancellationToken.None);

        table.Rows.Should().BeEmpty();
    }

    [Theory]
    [InlineData(false, 5, 5)]
    [InlineData(true, 5, 6)]
    [InlineData(true, 5, -1)]
    public void LegacyMigration_DoesNotClaimUnmatchedOrAlreadyMigratedRoutes(bool enabled, int first, int second)
    {
        var table = new MemoryRoutes();
        table.Rows[Pair[0]] = first;
        if (second >= 0) table.Rows[Pair[1]] = second;
        var changes = new List<BypassRouteChange>();

        new BypassRouteLeaseService(table).AdoptLegacyPair(Pair, changes, () => { }, enabled);

        changes.Should().BeEmpty();
    }

    [Fact]
    public void Restart_RetainsCleanupInState_ButRuleRollbackCannotReplaceIt()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wgst-bypass-test-{Guid.NewGuid():N}.json");
        try
        {
            var state = new AppState([], [], [], BypassRouteChanges: [new(Pair[0], 5, null)],
                LegacyBypassRoutesMigrated: true);
            var store = new StateStore(path);
            store.Save(state);
            var loaded = store.Load();
            loaded.BypassRouteChanges.Should().Equal(state.BypassRouteChanges);
            loaded.LegacyBypassRoutesMigrated.Should().BeTrue();
            var rollback = RuleStateMutations.CloneForAppliedRollback(loaded, new([], [], []));
            rollback.BypassRouteChanges.Should().Equal(loaded.BypassRouteChanges);
            rollback.LegacyBypassRoutesMigrated.Should().BeTrue();
            rollback.BypassRouteChanges.Should().NotBeSameAs(loaded.BypassRouteChanges);
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    private sealed class MemoryRoutes : IBypassRouteTable
    {
        public Dictionary<BypassRouteKey, int> Rows { get; } = [];
        public BypassRouteKey? FailDelete { get; set; }
        public Action<BypassRouteKey>? BeforeWrite { get; set; }
        public int? ReadMetric(BypassRouteKey route) => Rows.TryGetValue(route, out var metric) ? metric : null;
        public void SetMetric(BypassRouteKey route, int metric)
        {
            BeforeWrite?.Invoke(route);
            Rows[route] = metric;
        }
        public void Delete(BypassRouteKey route)
        {
            if (route == FailDelete) throw new IOException("route delete failed");
            Rows.Remove(route);
        }
    }
}
