using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;
namespace WireguardSplitTunnel.Core.Tests;
public class SoftwareRoutingTests
{
    private static SoftwareRule Rule(bool children = true) => new("app.exe", true, DomainRouteMode.UseWireGuard, children, @"C:\apps\app.exe");
    private static SoftwareProcess P(int id, int parent, long time, string path) => new(id, parent, time, path);
    private static SoftwareConnectionSnapshot Snapshot(params SoftwareProcess[] p) => new(p, p.Select(x => new SoftwareTcpConnection(x.ProcessId, "8.8.8." + x.ProcessId)).ToArray());
    [Fact] public void Learns_recursive_children_but_not_unrelated_same_exe_and_matches_path_case_insensitively()
    {
        var plan = new SoftwareRoutePlanner().Observe([Rule()], [], Snapshot(P(1,0,1,@"c:\APPS\APP.exe"),P(2,1,2,@"C:\node.exe"),P(3,2,3,@"C:\worker.exe"),P(4,0,4,@"C:\node.exe"),P(5,0,5,@"D:\app.exe")), []);
        plan.Learned.Single().IpAddresses.Should().BeEquivalentTo("8.8.8.1","8.8.8.2","8.8.8.3");
        plan.ChildCounts.Values.Single().Should().Be(2);
    }
    [Fact] public void Toggle_children_invalidates_previous_learning_and_disabled_deleted_rules_disappear()
    {
        var planner=new SoftwareRoutePlanner(); var snapshot=Snapshot(P(1,0,1,@"C:\apps\app.exe"),P(2,1,2,@"C:\node.exe"));
        var first=planner.Observe([Rule()],[],snapshot,[]);
        planner.Observe([Rule(false)],first.Learned,snapshot,[]).Learned.Single().IpAddresses.Should().Equal("8.8.8.1");
        planner.Observe([Rule() with { Enabled=false }], first.Learned,snapshot,[]).Learned.Should().BeEmpty();
        planner.Observe([],first.Learned,snapshot,[]).Learned.Should().BeEmpty();
    }
    [Fact] public void Retains_known_child_after_parent_exit_but_reused_pid_and_older_child_are_not_descendants()
    {
        var planner=new SoftwareRoutePlanner();
        planner.Observe([Rule()],[],Snapshot(P(1,0,10,@"C:\apps\app.exe"),P(2,1,20,@"C:\node.exe")),[]);
        var next=planner.Observe([Rule()],[],Snapshot(P(2,1,20,@"C:\node.exe"),P(1,0,30,@"C:\other.exe"),P(3,1,5,@"C:\node.exe")),[]);
        next.Learned.Single().IpAddresses.Should().Equal("8.8.8.2");
        planner.Observe([Rule()],[],Snapshot(P(2,1,40,@"C:\node.exe")),[]).Learned.Single().IpAddresses.Should().BeEmpty();
    }
    [Theory] [InlineData("127.0.0.1")] [InlineData("10.0.0.1")] [InlineData("192.168.1.1")] [InlineData("172.16.0.1")] [InlineData("169.254.0.1")] [InlineData("100.64.0.1")] [InlineData("224.1.2.3")] [InlineData("0.0.0.0")] [InlineData("::1")] [InlineData("198.18.0.1")]
    public void Rejects_non_public_destinations(string ip) => SoftwareRoutePlanner.IsPublicIpv4(ip).Should().BeFalse();
    [Fact] public void Filters_transport_endpoints_including_previously_learned_addresses()
    {
        var r=Rule(); var old=new SoftwareLearnedDestinations(SoftwareRoutePlanner.Fingerprint(r), ["8.8.8.1"]);
        new SoftwareRoutePlanner().Observe([r],[old],Snapshot(P(1,0,1,@"C:\apps\app.exe")),["8.8.8.1"]).Learned.Single().IpAddresses.Should().BeEmpty();
    }
    [Fact] public void Snapshot_bracketing_rejects_pid_reuse_and_incomplete_identity()
    {
        var before=new[]{P(1,0,1,@"C:\apps\app.exe"), P(2,0,1,@"C:\other.exe")};
        var after=new[]{P(1,0,2,@"C:\other.exe"), P(2,0,1,@"C:\other.exe")};
        SoftwareConnectionSnapshot.Validate(before,[new(1,"8.8.8.8"),new(2,"1.1.1.1")],after).Connections.Should().ContainSingle().Which.ProcessId.Should().Be(2);
    }
    [Fact] public async Task Reconciler_retains_debt_retries_partial_failures_and_never_owns_preexisting_routes()
    {
        var writer=new Writer { FailAdd="1.1.1.1" }; var state=new List<SoftwareOwnedRoute>(); var r=new SoftwareRouteReconciler(writer);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>r.ReconcileAsync(["8.8.8.8","1.1.1.1"],[],7,state,()=>{},()=>true,default));
        state.Should().ContainSingle().Which.IpAddress.Should().Be("8.8.8.8");
        writer.FailAdd=null; writer.FailDelete=true;
        await Assert.ThrowsAsync<InvalidOperationException>(()=>r.ReconcileAsync([],[],7,state,()=>{},()=>true,default));
        state.Should().ContainSingle(); writer.FailDelete=false;
        await r.ReconcileAsync([],[],null,state,()=>{},()=>true,default); state.Should().BeEmpty();
        writer.Preexisting=true; await r.ReconcileAsync(["1.1.1.1"],[],7,state,()=>{},()=>true,default);state.Should().BeEmpty();
    }
    [Fact] public async Task Domain_overlap_survives_software_disable_and_stale_generation_writes_nothing()
    {
        var writer=new Writer(); var state=new List<SoftwareOwnedRoute>{new("8.8.8.8",7,"0.0.0.0",3)};var r=new SoftwareRouteReconciler(writer);
        await r.ReconcileAsync([], ["8.8.8.8"],7,state,()=>{},()=>true,default);state.Should().ContainSingle();writer.Deletes.Should().Be(0);
        await r.ReconcileAsync(["1.1.1.1"],[],7,state,()=>{},()=>false,default);writer.Adds.Should().Be(0);writer.Deletes.Should().Be(0);
        await r.ReconcileAsync(["1.1.1.1"],[],null,[],()=>{},()=>true,default); writer.Adds.Should().Be(0);
    }
    [Fact] public void State_clone_is_deep_and_rollback_preserves_current_cleanup_debt()
    {
        var state=new AppState([],[],[]);
        state.SoftwareLearnedDestinations.Add(new("key",["8.8.8.8"]));
        state.SoftwareOwnedRoutes.Add(new("8.8.8.8",7,"0.0.0.0",3));
        var clone=RuleStateMutations.Clone(state); clone.SoftwareLearnedDestinations[0].IpAddresses.Clear();clone.SoftwareOwnedRoutes.Clear();
        state.SoftwareLearnedDestinations[0].IpAddresses.Should().ContainSingle();state.SoftwareOwnedRoutes.Should().ContainSingle();
        RuleStateMutations.CloneForAppliedRollback(state,new AppState([],[],[])).SoftwareOwnedRoutes.Should().Equal(state.SoftwareOwnedRoutes);
    }
    [Fact] public async Task Missing_interface_preserves_enabled_ownership_and_prevents_new_additions()
    {
        var writer=new Writer();var owned=new List<SoftwareOwnedRoute>{new("8.8.8.8",7,"0.0.0.0",3)};
        await new SoftwareRouteReconciler(writer).ReconcileAsync(["8.8.8.8","1.1.1.1"],[],null,owned,()=>{},()=>true,default);
        owned.Should().ContainSingle();writer.Adds.Should().Be(0);writer.Deletes.Should().Be(0);
    }
    [Fact] public async Task Transfers_only_domain_ledger_owned_ips_and_persists_exact_tuple_before_release()
    {
        var owned=new List<SoftwareOwnedRoute>();var writer=new Writer();var saved=false;
        var transferred=await SoftwareDomainRouteOwnership.TransferAsync([new("old.example","8.8.8.8", "old", 7,"0.0.0.0",41)],["8.8.8.8","1.1.1.1"],7,owned,
            (key,_)=>Task.FromResult<SoftwareOwnedRoute?>(key with { Metric=41 }),writer,()=>{ owned.Should().ContainSingle();saved=true; },default);
        saved.Should().BeTrue();transferred.Should().Equal("8.8.8.8");owned.Single().Metric.Should().Be(41);
        var deletes=new Writer();await new SoftwareRouteReconciler(deletes).ReconcileAsync([], ["8.8.8.8"],7,owned,()=>{},()=>true,default);
        deletes.Deletes.Should().Be(0);
        await new SoftwareRouteReconciler(deletes).ReconcileAsync([],[],7,owned,()=>{},()=>true,default);deletes.Deletes.Should().Be(1);
    }
    [Fact] public async Task Transfer_missing_interface_and_failed_lookup_keep_domain_debt()
    {
        var owned=new List<SoftwareOwnedRoute>();var writer=new Writer();
        var result=await SoftwareDomainRouteOwnership.TransferAsync([new("old.example","8.8.8.8")],["8.8.8.8"],null,owned,
            (_,_)=>throw new Exception("must not query"),writer,()=>{},default);
        result.Should().BeEmpty();owned.Should().BeEmpty();
        await Assert.ThrowsAsync<InvalidOperationException>(()=>SoftwareDomainRouteOwnership.TransferAsync([new("old.example","8.8.8.8","old",7,"0.0.0.0",3)],["8.8.8.8"],7,owned,
            (_,_)=>throw new InvalidOperationException("lookup failed"),writer,()=>{},default));owned.Should().BeEmpty();
    }
    [Fact] public async Task Generation_change_after_confirmed_creation_records_debt_then_stops()
    {
        var writer=new Writer();var current=true;var owned=new List<SoftwareOwnedRoute>();
        await new SoftwareRouteReconciler(writer).ReconcileAsync(["8.8.8.8","1.1.1.1"],[],7,owned,()=>current=false,()=>current,default);
        writer.Adds.Should().Be(1);owned.Should().ContainSingle();
    }
    [Fact] public async Task Interface_switch_installs_domain_shared_replacement_before_removing_old_interface()
    {
        var owned=new List<SoftwareOwnedRoute>{new("8.8.8.8",7,"0.0.0.0",41)};
        var writer=new Writer();
        await new SoftwareRouteReconciler(writer).ReconcileAsync([], ["8.8.8.8"],9,owned,()=>{},()=>true,default);
        owned.Should().ContainSingle().Which.InterfaceIndex.Should().Be(9);writer.Adds.Should().Be(1);writer.Deletes.Should().Be(1);
    }
    [Fact] public async Task Failed_interface_replacement_preserves_old_route_debt()
    {
        var owned=new List<SoftwareOwnedRoute>{new("8.8.8.8",7,"0.0.0.0",41)};
        var writer=new Writer{ FailAdd="8.8.8.8" };
        await Assert.ThrowsAsync<InvalidOperationException>(()=>new SoftwareRouteReconciler(writer).ReconcileAsync(["8.8.8.8"], ["8.8.8.8"],9,owned,()=>{},()=>true,default));
        owned.Should().ContainSingle().Which.InterfaceIndex.Should().Be(7);writer.Deletes.Should().Be(0);
    }
    [Fact] public async Task Missing_legacy_shared_route_retires_domain_debt_without_adding_a_route()
    {
        var owned=new List<SoftwareOwnedRoute>();var writer=new Writer();
        var moved=await SoftwareDomainRouteOwnership.TransferAsync([new("old.example","8.8.8.8","old",7,"0.0.0.0",3)],["8.8.8.8"],7,owned,
            (_,_)=>Task.FromResult<SoftwareOwnedRoute?>(null),writer,()=>{},default);
        moved.Should().Equal("8.8.8.8");owned.Should().BeEmpty();writer.Adds.Should().Be(0);
    }
    [Fact] public async Task Transfer_uses_recorded_original_interface_and_never_adopts_current_interface_route()
    {
        var owned=new List<SoftwareOwnedRoute>();var writer=new Writer();
        var moved=await SoftwareDomainRouteOwnership.TransferAsync([new("old.example","8.8.8.8","A",7,"0.0.0.0",41)],["8.8.8.8"],9,owned,
            (key,_)=> { key.InterfaceIndex.Should().Be(7);return Task.FromResult<SoftwareOwnedRoute?>(key); },writer,()=>{},default);
        moved.Should().Equal("8.8.8.8");owned.Single().InterfaceIndex.Should().Be(7);
    }
    [Fact] public async Task Transfer_retains_legacy_or_replaced_tuple_without_adopting_it()
    {
        var owned=new List<SoftwareOwnedRoute>();var writer=new Writer();
        var legacy=await SoftwareDomainRouteOwnership.TransferAsync([new("old.example","8.8.8.8")],["8.8.8.8"],9,owned,
            (_,_)=>throw new Exception("must not guess"),writer,()=>{},default);
        legacy.Should().BeEmpty();
        var replaced=await SoftwareDomainRouteOwnership.TransferAsync([new("old.example","8.8.8.8","A",7,"0.0.0.0",41)],["8.8.8.8"],9,owned,
            (key,_)=>Task.FromResult<SoftwareOwnedRoute?>(key with { Metric=1 }),writer,()=>{},default);
        replaced.Should().BeEmpty();owned.Should().BeEmpty();
    }
    [Fact] public void Domain_renew_and_incremental_snapshot_merges_preserve_exact_metadata_repeatedly()
    {
        var ledger=new[]{new ManagedRouteEntry("old.example","8.8.8.8","Original",7,"0.0.0.0",41)};
        var renewed=SoftwareDomainRouteOwnership.PreserveMetadata([new("new.example","8.8.8.8")],ledger);
        var repeated=SoftwareDomainRouteOwnership.PreserveMetadata([new("new.example","8.8.8.8")],renewed);
        repeated.Should().Equal(renewed);repeated.Single().Domain.Should().Be("new.example");repeated.Single().InterfaceIndex.Should().Be(7);repeated.Single().RouteMetric.Should().Be(41);
    }
    [Fact] public async Task Transfer_save_failure_never_drops_the_original_domain_ledger()
    {
        var ledger=new[]{new ManagedRouteEntry("old.example","8.8.8.8","Original",7,"0.0.0.0",41)};var owned=new List<SoftwareOwnedRoute>();
        await Assert.ThrowsAsync<IOException>(()=>SoftwareDomainRouteOwnership.TransferAsync(ledger,["8.8.8.8"],9,owned,
            (key,_)=>Task.FromResult<SoftwareOwnedRoute?>(key),new Writer(),()=>throw new IOException("disk full"),default));
        ledger.Should().ContainSingle();owned.Should().ContainSingle().Which.InterfaceIndex.Should().Be(7);
    }
    [Fact] public void Public_addressed_connected_networks_are_excluded_including_previously_learned_ips()
    {
        var rule=Rule();var old=new SoftwareLearnedDestinations(SoftwareRoutePlanner.Fingerprint(rule),["8.8.8.8","9.9.9.9"]);
        var result=new SoftwareRoutePlanner().Observe([rule],[old],Snapshot(P(1,0,1,@"C:\apps\app.exe")),["8.8.8.123/24"]);
        result.Learned.Single().IpAddresses.Should().Equal("9.9.9.9");
    }
    [Fact] public void State_store_round_trip_keeps_learning_owned_routes_and_original_domain_tuple()
    {
        var path=Path.Combine(Path.GetTempPath(),"wgst-routing-"+Guid.NewGuid()+".json");
        try
        {
            var state=new AppState([],[],[new("example.test","8.8.8.8","Original",7,"0.0.0.0",41)]);
            state.SoftwareLearnedDestinations.Add(new("key",["9.9.9.9"]));state.SoftwareOwnedRoutes.Add(new("9.9.9.9",9,"0.0.0.0",3));
            var store=new StateStore(path);store.Save(state);var restored=store.Load();
            restored.SoftwareLearnedDestinations.Single().IpAddresses.Should().Equal("9.9.9.9");restored.SoftwareOwnedRoutes.Should().Equal(state.SoftwareOwnedRoutes);
            restored.ManagedRouteSnapshot.Should().Equal(state.ManagedRouteSnapshot);
            File.WriteAllText(path,"{\"DomainRules\":[],\"LastKnownResolvedIps\":{},\"ManagedRouteSnapshot\":[{\"Domain\":\"old.example\",\"IpAddress\":\"8.8.8.8\"}]}");
            var legacy=store.Load();legacy.SoftwareLearnedDestinations.Should().BeEmpty();legacy.SoftwareOwnedRoutes.Should().BeEmpty();legacy.ManagedRouteSnapshot.Single().InterfaceIndex.Should().BeNull();
        }
        finally { if(File.Exists(path)) File.Delete(path); }
    }
    [Fact] public void Incremental_domain_learning_reclaims_shared_debt_before_software_cleanup()
    {
        var rule=new DomainRule("*.example.test");
        var state=new AppState([rule],[],[new("__software_shared_route__","8.8.8.8","Original",7,"0.0.0.0",41)]);
        var plan=IncrementalDomainRouteApplyPlanner.Build(state,[new ResolvedRule(rule,["8.8.8.8"])]);
        plan.Snapshot.Single().Domain.Should().Be("*.example.test");plan.Snapshot.Single().InterfaceIndex.Should().Be(7);
    }
    [Fact] public void Domain_removal_distinguishes_original_A_tuple_from_software_owned_B_tuple()
    {
        var domainA=new ManagedRouteEntry("old.example","8.8.8.8","A",7,"0.0.0.0",41);
        var softwareB=new SoftwareOwnedRoute("8.8.8.8",9,"0.0.0.0",3);
        SoftwareDomainRouteOwnership.CanRemoveDomainRoute(domainA,[],[softwareB]).Should().BeTrue();
        SoftwareDomainRouteOwnership.CanRemoveDomainRoute(domainA,["8.8.8.8"],[softwareB]).Should().BeFalse();
        SoftwareDomainRouteOwnership.CanRemoveDomainRoute(domainA,[],[new("8.8.8.8",7,"0.0.0.0",41)]).Should().BeFalse();
        SoftwareDomainRouteOwnership.CanRemoveDomainRoute(new("old.example","8.8.8.8"),[],[softwareB]).Should().BeFalse();
    }
    [Fact] public async Task Removing_domain_A_and_disabling_software_B_cleans_both_exact_routes()
    {
        var a=new ManagedRouteEntry("old.example","8.8.8.8","A",7,"0.0.0.0",41);
        var owned=new List<SoftwareOwnedRoute>{new("8.8.8.8",9,"0.0.0.0",3)};var writer=new Writer();
        SoftwareDomainRouteOwnership.RetainSharedDebt([], [a], [], owned).Should().BeEmpty();
        if(SoftwareDomainRouteOwnership.CanRemoveDomainRoute(a,[],owned)) await writer.DeleteAsync(new(a.IpAddress,a.InterfaceIndex!.Value,a.NextHop!,a.RouteMetric!.Value),default);
        await new SoftwareRouteReconciler(writer).ReconcileAsync([],[],9,owned,()=>{},()=>true,default);
        writer.Deletes.Should().Be(2);owned.Should().BeEmpty();
    }
    [Fact] public void Removing_legacy_domain_with_other_interface_software_owner_preserves_debt_across_renewals()
    {
        var owned=new[]{new SoftwareOwnedRoute("8.8.8.8",9,"0.0.0.0",3)};
        var first=SoftwareDomainRouteOwnership.RetainSharedDebt([], [new("old.example","8.8.8.8")], [], owned);
        first.Should().ContainSingle().Which.Domain.Should().Be(SoftwareDomainRouteOwnership.SharedDebtDomain);
        SoftwareDomainRouteOwnership.RetainSharedDebt([],first,[],[]).Should().Equal(first);
    }
    private sealed class Writer:ISoftwareRouteWriter
    {
        public string? FailAdd; public bool FailDelete,Preexisting; public int Adds,Deletes;
        public Task<bool> EnsureAsync(SoftwareOwnedRoute route,CancellationToken ct) { Adds++; if(route.IpAddress==FailAdd) throw new InvalidOperationException(); return Task.FromResult(!Preexisting); }
        public Task DeleteAsync(SoftwareOwnedRoute route,CancellationToken ct) { Deletes++;if(FailDelete)throw new InvalidOperationException();return Task.CompletedTask; }
    }
}
