using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Platform;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacCleanupStateReducerTests
{
    private static readonly AppState StateWithCleanupDebt = new AppState(
        [],
        [],
        [
            new ManagedRouteEntry("one.example", "198.51.100.10", "utun4"),
            new ManagedRouteEntry("two.example", "198.51.100.20", "utun4"),
            new ManagedRouteEntry("legacy.example", "198.51.100.30")
        ]) with
    {
        ActiveSplitTunnelConfigPath = "/data/wgst-split.conf",
        ActiveRawTunnelName = "SG"
    };

    private static readonly MacCleanupRequest FullRequest = new()
    {
        SplitConfigPath = "/data/wgst-split.conf",
        RawTunnelName = "SG",
        ManagedRoutesToRemove =
        [
            new ManagedRouteEntry("one.example", "198.51.100.10", "utun4"),
            new ManagedRouteEntry("two.example", "198.51.100.20", "utun4"),
            new ManagedRouteEntry("legacy.example", "198.51.100.30")
        ]
    };

    [Fact]
    public void Apply_CancelledDisable_PreservesEveryCleanupDebt()
    {
        var updated = MacCleanupStateReducer.Apply(
            StateWithCleanupDebt,
            FullRequest,
            new MacCleanupResult { Cancelled = true });

        updated.ActiveSplitTunnelConfigPath.Should().Be("/data/wgst-split.conf");
        updated.ActiveRawTunnelName.Should().Be("SG");
        updated.ManagedRouteSnapshot.Should().Equal(StateWithCleanupDebt.ManagedRouteSnapshot);
    }

    [Fact]
    public void Apply_UnknownRawMappingAndFailedCleanup_PreservesRawDebt()
    {
        MacTunnelLifecyclePlanner.ShouldAttemptCleanup(MacTunnelMappingPresence.Unknown)
            .Should().BeTrue();

        var updated = MacCleanupStateReducer.Apply(
            StateWithCleanupDebt,
            FullRequest,
            new MacCleanupResult { Prompted = true });

        updated.ActiveRawTunnelName.Should().Be("SG");
        updated.ActiveSplitTunnelConfigPath.Should().Be("/data/wgst-split.conf");
    }

    [Fact]
    public void Apply_OnlyExactSuccessfulTunnelStops_ClearTheirOwnershipDebt()
    {
        var updated = MacCleanupStateReducer.Apply(
            StateWithCleanupDebt,
            FullRequest,
            new MacCleanupResult
            {
                Prompted = true,
                SplitTunnelStopped = true,
                RawTunnelStopped = false
            });

        updated.ActiveSplitTunnelConfigPath.Should().BeNull();
        updated.ActiveRawTunnelName.Should().Be("SG");
    }

    [Fact]
    public void Apply_RouteOutcomes_RemoveOnlyExactResolvedDebtAndPreserveLegacyDebt()
    {
        var updated = MacCleanupStateReducer.Apply(
            StateWithCleanupDebt,
            FullRequest,
            new MacCleanupResult
            {
                Prompted = true,
                AlreadyAbsentManagedRoutes =
                [
                    new ManagedRouteEntry("one.example", "198.51.100.10", "utun4")
                ],
                ReplacedManagedRoutes =
                [
                    new ManagedRouteEntry("two.example", "198.51.100.20", "utun4")
                ]
            });

        updated.ManagedRouteSnapshot.Should().Equal(
            new ManagedRouteEntry("legacy.example", "198.51.100.30"));
    }

    [Fact]
    public void BuildCleanupBatch_MissingWgQuick_DoesNotReportTunnelCleanupSuccess()
    {
        var batch = MacExitCleanupService.BuildCleanupBatch(null, FullRequest);

        batch.Script.Should().Contain("/sbin/route");
        batch.Script.Should().NotContain("wg-quick");

        var result = MacExitCleanupService.ParseCleanupResult(
            FullRequest,
            batch,
            new MacShellResult(0, string.Empty, string.Empty));

        result.SplitTunnelStopped.Should().BeFalse();
        result.RawTunnelStopped.Should().BeFalse();
        MacCleanupStateReducer.Apply(StateWithCleanupDebt, FullRequest, result)
            .ActiveRawTunnelName.Should().Be("SG");
    }

    [Fact]
    public void Apply_PartialDnsRestore_ClearsOnlySuccessfulServiceDebt()
    {
        var wifi = new MacDnsServiceSnapshot("Wi-Fi", ["1.1.1.1"], ["home.arpa"]);
        var ethernet = new MacDnsServiceSnapshot("Ethernet", [], []);
        var debt = new MacRawTunnelDnsCleanupDebt(
            "SG",
            "/opt/homebrew/etc/wireguard/SG.conf",
            ["103.86.96.100"],
            [],
            [wifi, ethernet]);
        var state = StateWithCleanupDebt with { RawTunnelDnsCleanupDebt = debt };
        var request = FullRequest with
        {
            DnsRestorePlan = new MacDnsRestorePlan
            {
                TunnelName = debt.TunnelName,
                ConfigPath = debt.ConfigPath,
                DnsServersToRestore = [wifi, ethernet],
                SearchDomainsToRestore = [wifi, ethernet]
            }
        };

        var updated = MacCleanupStateReducer.Apply(
            state,
            request,
            new MacCleanupResult
            {
                Prompted = true,
                RestoredDnsServerServices = ["Wi-Fi"],
                RestoredSearchDomainServices = ["Wi-Fi"]
            });

        updated.RawTunnelDnsCleanupDebt.Should().NotBeNull();
        updated.RawTunnelDnsCleanupDebt!.Services.Should().Equal(ethernet);
    }

    [Fact]
    public void Apply_FailedDnsRestore_PreservesExactSnapshotDebt()
    {
        var wifi = new MacDnsServiceSnapshot("Wi-Fi", ["1.1.1.1"], ["home.arpa"]);
        var debt = new MacRawTunnelDnsCleanupDebt(
            "SG",
            "/opt/homebrew/etc/wireguard/SG.conf",
            ["103.86.96.100"],
            [],
            [wifi]);
        var state = StateWithCleanupDebt with { RawTunnelDnsCleanupDebt = debt };
        var request = FullRequest with
        {
            DnsRestorePlan = new MacDnsRestorePlan
            {
                TunnelName = debt.TunnelName,
                ConfigPath = debt.ConfigPath,
                DnsServersToRestore = [wifi],
                SearchDomainsToRestore = [wifi]
            }
        };

        var updated = MacCleanupStateReducer.Apply(
            state,
            request,
            new MacCleanupResult { Prompted = true });

        updated.RawTunnelDnsCleanupDebt.Should().BeEquivalentTo(debt);
    }

    [Fact]
    public void Apply_DnsSuccessAndSearchFailure_PreservesOnlySearchDomainDebtForRetry()
    {
        var wifi = new MacDnsServiceSnapshot("Wi-Fi", ["1.1.1.1"], ["home.arpa"]);
        var debt = new MacRawTunnelDnsCleanupDebt(
            "SG",
            "/opt/homebrew/etc/wireguard/SG.conf",
            ["103.86.96.100"],
            ["tailnet.ts.net"],
            [wifi]);
        var state = StateWithCleanupDebt with { RawTunnelDnsCleanupDebt = debt };
        var request = FullRequest with
        {
            DnsRestorePlan = new MacDnsRestorePlan
            {
                TunnelName = debt.TunnelName,
                ConfigPath = debt.ConfigPath,
                DnsServersToRestore = [wifi],
                SearchDomainsToRestore = [wifi]
            }
        };

        var updated = MacCleanupStateReducer.Apply(
            state,
            request,
            new MacCleanupResult
            {
                Prompted = true,
                RestoredDnsServerServices = ["Wi-Fi"]
            });

        updated.RawTunnelDnsCleanupDebt.Should().NotBeNull();
        updated.RawTunnelDnsCleanupDebt!.Services.Should().ContainSingle()
            .Which.Should().BeEquivalentTo(wifi with
            {
                RestoreDnsServersPending = false,
                RestoreSearchDomainsPending = true
            });

        var retry = MacDnsRepairService.PlanSnapshotRestore(
            updated.RawTunnelDnsCleanupDebt,
            new Dictionary<string, MacDnsServiceSnapshot>(StringComparer.OrdinalIgnoreCase)
            {
                ["Wi-Fi"] = new("Wi-Fi", ["1.1.1.1"], ["tailnet.ts.net"])
            });
        retry.DnsServersToRestore.Should().BeEmpty();
        retry.SearchDomainsToRestore.Should().ContainSingle();
    }
}
