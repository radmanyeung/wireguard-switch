using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Platform;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacExitCleanupServiceTests
{
    private const string WgQuick = "/opt/homebrew/bin/wg-quick";

    [Fact]
    public void BuildCleanupBatch_AllInputs_EmitsTrackedCommandsInComponentOrder()
    {
        var request = new MacCleanupRequest
        {
            SplitConfigPath = "/data/wgst-split.conf",
            RawTunnelName = "SG",
            ManagedRoutesToRemove =
            [
                new ManagedRouteEntry("one.example", "1.2.3.4", "utun4"),
                new ManagedRouteEntry("two.example", "5.6.7.8", "utun4")
            ],
            DnsRestorePlan = new MacDnsRestorePlan
            {
                TunnelName = "SG",
                ConfigPath = "/config/SG.conf",
                DnsServersToRestore = [new MacDnsServiceSnapshot("Wi-Fi", [], [])],
                SearchDomainsToRestore = [new MacDnsServiceSnapshot("Wi-Fi", [], [])]
            }
        };

        var batch = MacExitCleanupService.BuildCleanupBatch(WgQuick, request);

        batch.Operations.Select(operation => operation.Kind).Should().Equal(
            MacCleanupOperationKind.ManagedRoute,
            MacCleanupOperationKind.ManagedRoute,
            MacCleanupOperationKind.SplitTunnel,
            MacCleanupOperationKind.RawTunnel,
            MacCleanupOperationKind.DnsServers,
            MacCleanupOperationKind.SearchDomains);
        batch.Script.Should().Contain("\"/opt/homebrew/bin/wg-quick\" down \"/data/wgst-split.conf\"");
        batch.Script.Should().Contain("\"/opt/homebrew/bin/wg-quick\" down \"SG\"");
        batch.Script.Should().Contain("/sbin/route -n get \"1.2.3.4\"");
        batch.Script.Should().Contain("/sbin/route -n delete -host \"1.2.3.4\"");
        batch.Script.IndexOf("/sbin/route -n get", StringComparison.Ordinal)
            .Should().BeLessThan(batch.Script.IndexOf("wg-quick", StringComparison.Ordinal));
        batch.Script.Should().Contain("/usr/sbin/networksetup -setdnsservers \"Wi-Fi\" Empty");
        batch.Script.Should().NotContain("|| true");
    }

    [Fact]
    public void BuildCleanupBatch_NoInputs_ReturnsEmpty()
    {
        var batch = MacExitCleanupService.BuildCleanupBatch(WgQuick, new MacCleanupRequest());

        batch.Script.Should().BeEmpty();
        batch.Operations.Should().BeEmpty();
    }

    [Fact]
    public void BuildCleanupBatch_NoWgQuick_LeavesTunnelDebtButKeepsRouteCleanup()
    {
        var batch = MacExitCleanupService.BuildCleanupBatch(
            null,
            new MacCleanupRequest
            {
                SplitConfigPath = "/data/wgst-split.conf",
                RawTunnelName = "SG",
                ManagedRoutesToRemove =
                [
                    new ManagedRouteEntry("one.example", "1.2.3.4", "utun4")
                ]
            });

        batch.Script.Should().NotContain("wg-quick");
        batch.Script.Should().Contain("/sbin/route -n delete -host \"1.2.3.4\"");
        batch.Operations.Should().ContainSingle()
            .Which.Kind.Should().Be(MacCleanupOperationKind.ManagedRoute);
    }

    [Fact]
    public void BuildCleanupBatch_QuotesExactDnsAndSearchDomainSnapshot()
    {
        var batch = MacExitCleanupService.BuildCleanupBatch(
            WgQuick,
            new MacCleanupRequest
            {
                SplitConfigPath = "/Users/u/Application Support/wgst-split.conf",
                DnsRestorePlan = new MacDnsRestorePlan
                {
                    DnsServersToRestore =
                    [
                        new MacDnsServiceSnapshot(
                            "My Service",
                            ["1.1.1.1", "9.9.9.9"],
                            ["home.arpa", "tailnet.ts.net"])
                    ],
                    SearchDomainsToRestore =
                    [
                        new MacDnsServiceSnapshot(
                            "My Service",
                            ["1.1.1.1", "9.9.9.9"],
                            ["home.arpa", "tailnet.ts.net"])
                    ]
                }
            });

        batch.Script.Should().Contain("down \"/Users/u/Application Support/wgst-split.conf\"");
        batch.Script.Should().Contain(
            "-setdnsservers \"My Service\" \"1.1.1.1\" \"9.9.9.9\"");
        batch.Script.Should().Contain(
            "-setsearchdomains \"My Service\" \"home.arpa\" \"tailnet.ts.net\"");
    }

    [Fact]
    public void BuildCleanupBatch_DnsAndSearchDomainsHaveIndependentOperations()
    {
        var snapshot = new MacDnsServiceSnapshot(
            "Wi-Fi",
            ["1.1.1.1"],
            ["home.arpa"]);
        var batch = MacExitCleanupService.BuildCleanupBatch(
            WgQuick,
            new MacCleanupRequest
            {
                DnsRestorePlan = new MacDnsRestorePlan
                {
                    DnsServersToRestore = [snapshot],
                    SearchDomainsToRestore = [snapshot]
                }
            });

        batch.Operations.Select(operation => operation.Kind).Should().Equal(
            MacCleanupOperationKind.DnsServers,
            MacCleanupOperationKind.SearchDomains);

        var dns = batch.Operations[0];
        var result = MacExitCleanupService.ParseCleanupResult(
            new MacCleanupRequest
            {
                DnsRestorePlan = new MacDnsRestorePlan
                {
                    DnsServersToRestore = [snapshot],
                    SearchDomainsToRestore = [snapshot]
                }
            },
            batch,
            new MacShellResult(1, dns.SuccessMarker, string.Empty));

        result.RestoredDnsServerServices.Should().Equal("Wi-Fi");
        result.RestoredSearchDomainServices.Should().BeEmpty();
        result.BatchCompleted.Should().BeFalse();
    }

    [Fact]
    public void ParseCleanupResult_PartialMarkers_ReportOnlyExactSuccesses()
    {
        var request = new MacCleanupRequest
        {
            RawTunnelName = "SG",
            ManagedRoutesToRemove =
            [
                new ManagedRouteEntry("one.example", "1.2.3.4", "utun4"),
                new ManagedRouteEntry("two.example", "5.6.7.8", "utun4")
            ],
            DnsRestorePlan = new MacDnsRestorePlan
            {
                DnsServersToRestore =
                [
                    new MacDnsServiceSnapshot("Wi-Fi", [], []),
                    new MacDnsServiceSnapshot("Ethernet", [], [])
                ],
                SearchDomainsToRestore =
                [
                    new MacDnsServiceSnapshot("Wi-Fi", [], []),
                    new MacDnsServiceSnapshot("Ethernet", [], [])
                ]
            }
        };
        var batch = MacExitCleanupService.BuildCleanupBatch(WgQuick, request);
        var route = batch.Operations.Single(operation => operation.Target == "1.2.3.4");
        var wifi = batch.Operations.Single(operation =>
            operation.Target == "Wi-Fi"
            && operation.Kind == MacCleanupOperationKind.DnsServers);
        var successes = new[]
        {
            route.OutcomeMarker(MacManagedRouteCleanupDisposition.AlreadyAbsent),
            wifi.SuccessMarker
        };

        var result = MacExitCleanupService.ParseCleanupResult(
            request,
            batch,
            new MacShellResult(0, string.Join('\n', successes), string.Empty));

        result.RawTunnelStopped.Should().BeFalse();
        result.AlreadyAbsentManagedRoutes.Should().Equal(
            new ManagedRouteEntry("one.example", "1.2.3.4", "utun4"));
        result.DeletedManagedRoutes.Should().BeEmpty();
        result.RestoredDnsServices.Should().Equal("Wi-Fi");
    }

    [Fact]
    public void ParseCleanupResult_ReplacedRouteMarker_ResolvesDebtWithoutDeletingReplacement()
    {
        var route = new ManagedRouteEntry("one.example", "1.2.3.4", "utun4");
        var request = new MacCleanupRequest { ManagedRoutesToRemove = [route] };
        var batch = MacExitCleanupService.BuildCleanupBatch(WgQuick, request);
        var operation = batch.Operations.Should().ContainSingle().Subject;

        var result = MacExitCleanupService.ParseCleanupResult(
            request,
            batch,
            new MacShellResult(
                0,
                operation.OutcomeMarker(MacManagedRouteCleanupDisposition.ReplacedByOtherInterface),
                string.Empty));

        result.ReplacedManagedRoutes.Should().Equal(route);
        result.DeletedManagedRoutes.Should().BeEmpty();
        batch.Script.Should().Contain("destination:");
        batch.Script.Should().Contain("interface:");
    }

    [Fact]
    public void BuildCleanupBatch_LegacyRouteWithoutExactInterface_RemainsDebt()
    {
        var batch = MacExitCleanupService.BuildCleanupBatch(
            WgQuick,
            new MacCleanupRequest
            {
                ManagedRoutesToRemove =
                [
                    new ManagedRouteEntry("legacy.example", "1.2.3.4")
                ]
            });

        batch.Script.Should().BeEmpty();
        batch.Operations.Should().BeEmpty();
    }

    [Fact]
    public void ParseCleanupResult_DuplicateLegacyIp_DoesNotResolveUnknownOwnership()
    {
        var owned = new ManagedRouteEntry("owned.example", "1.2.3.4", "utun4");
        var legacy = new ManagedRouteEntry("legacy.example", "1.2.3.4");
        var request = new MacCleanupRequest { ManagedRoutesToRemove = [owned, legacy] };
        var batch = MacExitCleanupService.BuildCleanupBatch(WgQuick, request);
        var operation = batch.Operations.Should().ContainSingle().Subject;

        var result = MacExitCleanupService.ParseCleanupResult(
            request,
            batch,
            new MacShellResult(
                0,
                operation.OutcomeMarker(MacManagedRouteCleanupDisposition.AlreadyAbsent),
                string.Empty));

        result.AlreadyAbsentManagedRoutes.Should().Equal(owned);
        result.AlreadyAbsentManagedRoutes.Should().NotContain(legacy);
    }

    [Fact]
    public void BuildCleanupBatch_MaliciousBareRawName_IsNeverElevated()
    {
        var batch = MacExitCleanupService.BuildCleanupBatch(
            WgQuick,
            new MacCleanupRequest
            {
                RawTunnelName = "x\"; /usr/bin/touch /tmp/pwned; #"
            });

        batch.Script.Should().BeEmpty();
        batch.Operations.Should().BeEmpty();
    }
}
