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
            ManagedIpsToRemove = ["1.2.3.4", "5.6.7.8"],
            DnsRestorePlan = new MacDnsRestorePlan
            {
                TunnelName = "SG",
                ConfigPath = "/config/SG.conf",
                ServicesToRestore = [new MacDnsServiceSnapshot("Wi-Fi", [], [])]
            }
        };

        var batch = MacExitCleanupService.BuildCleanupBatch(WgQuick, request);

        batch.Operations.Select(operation => operation.Kind).Should().Equal(
            MacCleanupOperationKind.SplitTunnel,
            MacCleanupOperationKind.RawTunnel,
            MacCleanupOperationKind.ManagedRoute,
            MacCleanupOperationKind.ManagedRoute,
            MacCleanupOperationKind.DnsService);
        batch.Script.Should().Contain("\"/opt/homebrew/bin/wg-quick\" down \"/data/wgst-split.conf\"");
        batch.Script.Should().Contain("\"/opt/homebrew/bin/wg-quick\" down \"SG\"");
        batch.Script.Should().Contain("/sbin/route -n delete -host \"1.2.3.4\"");
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
                ManagedIpsToRemove = ["1.2.3.4"]
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
                    ServicesToRestore =
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
    public void ParseCleanupResult_PartialMarkers_ReportOnlyExactSuccesses()
    {
        var request = new MacCleanupRequest
        {
            RawTunnelName = "SG",
            ManagedIpsToRemove = ["1.2.3.4", "5.6.7.8"],
            DnsRestorePlan = new MacDnsRestorePlan
            {
                ServicesToRestore =
                [
                    new MacDnsServiceSnapshot("Wi-Fi", [], []),
                    new MacDnsServiceSnapshot("Ethernet", [], [])
                ]
            }
        };
        var batch = MacExitCleanupService.BuildCleanupBatch(WgQuick, request);
        var successes = batch.Operations
            .Where(operation =>
                operation.Target is "1.2.3.4" or "Wi-Fi")
            .Select(operation => operation.SuccessMarker);

        var result = MacExitCleanupService.ParseCleanupResult(
            request,
            batch,
            new MacShellResult(0, string.Join('\n', successes), string.Empty));

        result.RawTunnelStopped.Should().BeFalse();
        result.RemovedManagedIps.Should().Equal("1.2.3.4");
        result.RestoredDnsServices.Should().Equal("Wi-Fi");
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
