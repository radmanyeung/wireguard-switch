using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacDnsRepairServiceTests
{
    [Fact]
    public void ParseDnsServers_IpPerLine_ReturnsIps()
    {
        MacDnsRepairService.ParseDnsServers("103.86.96.100\n103.86.99.100\n")
            .Should().Equal("103.86.96.100", "103.86.99.100");
    }

    [Fact]
    public void ParseDnsServers_NoneSetSentence_ReturnsEmpty()
    {
        MacDnsRepairService.ParseDnsServers("There aren't any DNS Servers set on Wi-Fi.")
            .Should().BeEmpty();
    }

    [Fact]
    public void ParseSearchDomains_ExactDomainLines_ReturnsDomains()
    {
        MacDnsRepairService.ParseSearchDomains("tailnet.ts.net\ncorp.example\n")
            .Should().Equal("tailnet.ts.net", "corp.example");
    }

    [Fact]
    public void CreateCleanupDebt_ConfigWithPrivateKey_PersistsOnlyDnsAndConfigProvenance()
    {
        const string config = """
            [Interface]
            PrivateKey = do-not-persist-this-key
            DNS = 103.86.96.100, tailnet.ts.net
            """;
        var before = new[]
        {
            new MacDnsServiceSnapshot("Wi-Fi", ["1.1.1.1"], ["home.arpa"])
        };

        var debt = MacDnsRepairService.CreateCleanupDebt(
            "SG",
            "/opt/homebrew/etc/wireguard/SG.conf",
            config,
            before);

        debt.Should().NotBeNull();
        debt!.TunnelName.Should().Be("SG");
        debt.ConfigPath.Should().Be("/opt/homebrew/etc/wireguard/SG.conf");
        debt.TunnelDnsServers.Should().Equal("103.86.96.100");
        debt.TunnelSearchDomains.Should().Equal("tailnet.ts.net");
        debt.ToString().Should().NotContain("do-not-persist-this-key");
    }

    [Fact]
    public void PlanSnapshotRestore_PreExistingMatchingDns_DoesNotScheduleRestore()
    {
        var snapshot = new MacDnsServiceSnapshot(
            "Wi-Fi",
            ["103.86.96.100"],
            ["tailnet.ts.net"]);
        var debt = CreateDebt(snapshot);
        var current = new Dictionary<string, MacDnsServiceSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            ["Wi-Fi"] = snapshot
        };

        var plan = MacDnsRepairService.PlanSnapshotRestore(debt, current);

        plan.ServicesToRestore.Should().BeEmpty();
        plan.ServicesResolvedWithoutRestore.Should().Equal("Wi-Fi");
    }

    [Fact]
    public void PlanSnapshotRestore_SelectedConfigMismatch_UsesPersistedRawConfigProvenance()
    {
        var before = new MacDnsServiceSnapshot("Wi-Fi", ["1.1.1.1"], ["home.arpa"]);
        var debt = CreateDebt(before);
        var current = new Dictionary<string, MacDnsServiceSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            ["Wi-Fi"] = new("Wi-Fi", ["103.86.96.100"], ["tailnet.ts.net"])
        };

        var plan = MacDnsRepairService.PlanSnapshotRestore(debt, current);

        plan.TunnelName.Should().Be("SG");
        plan.ConfigPath.Should().Be("/opt/homebrew/etc/wireguard/SG.conf");
        plan.ServicesToRestore.Should().Equal(before);
    }

    [Fact]
    public void PlanSnapshotRestore_SplitOnlyState_NeverSchedulesDnsRepair()
    {
        MacDnsRepairService.PlanSnapshotRestore(null, null)
            .ServicesToRestore.Should().BeEmpty();
    }

    [Fact]
    public void PlanSnapshotRestore_CurrentMagicDnsOwnedByAnotherVpn_DoesNotOverwriteIt()
    {
        var before = new MacDnsServiceSnapshot("Wi-Fi", ["1.1.1.1"], ["home.arpa"]);
        var current = new Dictionary<string, MacDnsServiceSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            ["Wi-Fi"] = new("Wi-Fi", ["100.100.100.100"], ["tail-scale.ts.net"])
        };

        var plan = MacDnsRepairService.PlanSnapshotRestore(CreateDebt(before), current);

        plan.ServicesToRestore.Should().BeEmpty();
        plan.ServicesResolvedWithoutRestore.Should().Equal("Wi-Fi");
    }

    [Fact]
    public void PlanSnapshotRestore_MixedRetry_RestoresOnlyStillTunnelOwnedSearchDomains()
    {
        var before = new MacDnsServiceSnapshot("Wi-Fi", ["1.1.1.1"], ["home.arpa"]);
        var debt = CreateDebt(before with { RestoreDnsServersPending = false });
        var current = new Dictionary<string, MacDnsServiceSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            ["Wi-Fi"] = new("Wi-Fi", ["1.1.1.1"], ["tailnet.ts.net"])
        };

        var plan = MacDnsRepairService.PlanSnapshotRestore(debt, current);

        plan.DnsServersToRestore.Should().BeEmpty();
        plan.SearchDomainsToRestore.Should().Equal(before with { RestoreDnsServersPending = false });
    }

    [Fact]
    public void PlanSnapshotRestore_OrderOnlyDifference_IsNotCollapsedAsSetEquality()
    {
        var before = new MacDnsServiceSnapshot(
            "Wi-Fi",
            ["103.86.99.100", "103.86.96.100"],
            ["tailnet.ts.net"]);
        var debt = new MacRawTunnelDnsCleanupDebt(
            "SG",
            "/opt/homebrew/etc/wireguard/SG.conf",
            ["103.86.96.100", "103.86.99.100"],
            ["tailnet.ts.net"],
            [before]);
        var current = new Dictionary<string, MacDnsServiceSnapshot>(StringComparer.OrdinalIgnoreCase)
        {
            ["Wi-Fi"] = new(
                "Wi-Fi",
                ["103.86.96.100", "103.86.99.100"],
                ["tailnet.ts.net"])
        };

        var plan = MacDnsRepairService.PlanSnapshotRestore(debt, current);

        plan.DnsServersToRestore.Should().Equal(before);
    }

    private static MacRawTunnelDnsCleanupDebt CreateDebt(MacDnsServiceSnapshot snapshot) =>
        new(
            "SG",
            "/opt/homebrew/etc/wireguard/SG.conf",
            ["103.86.96.100"],
            ["tailnet.ts.net"],
            [snapshot]);
}
