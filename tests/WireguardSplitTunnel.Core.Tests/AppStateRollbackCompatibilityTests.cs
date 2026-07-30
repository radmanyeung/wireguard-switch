using System.Text.Json;
using FluentAssertions;
using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class AppStateRollbackCompatibilityTests
{
    [Fact]
    public void V019Reader_IgnoresAutoUpdateEnabledAndPreservesRuleDomainAndIpSemantics()
    {
        var currentState = new AppState(
            [new DomainRule("chatgpt.com", true, DomainRouteMode.UseWireGuard)],
            new Dictionary<string, List<string>> { ["chatgpt.com"] = ["203.0.113.40"] },
            [new ManagedRouteEntry("chatgpt.com", "203.0.113.40", "wg0")]) with
            {
                AutoUpdateEnabled = false,
                SoftwareRules = [new SoftwareRule("chatgpt.exe", true, DomainRouteMode.UseWireGuard, true)]
            };

        var json = JsonSerializer.Serialize(currentState);
        var v019State = JsonSerializer.Deserialize<V019AppState>(json);

        json.Should().Contain("\"AutoUpdateEnabled\":false");
        v019State.Should().NotBeNull();
        v019State!.DomainRules.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(new DomainRule("chatgpt.com", true, DomainRouteMode.UseWireGuard));
        v019State.LastKnownResolvedIps["chatgpt.com"].Should().Equal("203.0.113.40");
        v019State.ManagedRouteSnapshot.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(new ManagedRouteEntry("chatgpt.com", "203.0.113.40", "wg0"));
        v019State.SoftwareRules.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(new SoftwareRule("chatgpt.exe", true, DomainRouteMode.UseWireGuard, true));
    }

    private sealed record V019AppState(
        List<DomainRule> DomainRules,
        Dictionary<string, List<string>> LastKnownResolvedIps,
        List<ManagedRouteEntry> ManagedRouteSnapshot,
        string? SelectedTunnelConfigPath = null,
        bool AutoEnableTunnel = false,
        List<SoftwareRule>? SoftwareRules = null,
        DomainRouteMode DomainGlobalDefaultMode = DomainRouteMode.BypassWireGuard,
        DomainRouteMode SoftwareGlobalDefaultMode = DomainRouteMode.BypassWireGuard,
        bool RestoreNormalRoutingOnExit = false,
        Dictionary<string, List<ResolvedIpDetail>>? LastKnownResolvedIpDetails = null,
        List<MacTunnelProfile>? MacTunnelProfiles = null,
        List<MacSoftwareRule>? MacSoftwareRules = null,
        List<MacDomainProfileAssignment>? MacDomainProfileAssignments = null,
        string? ActiveRawTunnelName = null,
        string? ActiveSplitTunnelConfigPath = null,
        MacRawTunnelDnsCleanupDebt? RawTunnelDnsCleanupDebt = null);
}
