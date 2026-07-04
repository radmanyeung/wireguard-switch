using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class MacQuickStartServiceTests
{
    [Fact]
    public void PlanStart_BlocksWhenAnotherVpnOwnsDefaultRoute()
    {
        var result = MacQuickStartService.PlanStart(
            defaultRouteInterfaceName: "utun4",
            savedConfigPath: "/opt/homebrew/etc/wireguard/SG.conf",
            discoveredConfigPaths: ["/opt/homebrew/etc/wireguard/SG.conf"]);

        result.Status.Should().Be(MacQuickStartStatus.BlockedByOtherVpn);
        result.ShouldStartTunnel.Should().BeFalse();
        result.SelectedConfigPath.Should().BeNull();
        result.Message.Should().Contain("Disconnect");
    }

    [Fact]
    public void PlanStart_SelectsConfigAndStartsTunnelOnNormalNetwork()
    {
        var result = MacQuickStartService.PlanStart(
            defaultRouteInterfaceName: "en0",
            savedConfigPath: "/opt/homebrew/etc/wireguard/SG.conf",
            discoveredConfigPaths: ["/opt/homebrew/etc/wireguard/SG.conf"]);

        result.Status.Should().Be(MacQuickStartStatus.Success);
        result.ShouldStartTunnel.Should().BeTrue();
        result.SelectedConfigPath.Should().Be("/opt/homebrew/etc/wireguard/SG.conf");
        result.Message.Should().Contain("SG.conf");
    }

    [Fact]
    public void PlanStart_StartsTunnelWhenDefaultRouteUnknown()
    {
        var result = MacQuickStartService.PlanStart(
            defaultRouteInterfaceName: null,
            savedConfigPath: "/opt/homebrew/etc/wireguard/SG.conf",
            discoveredConfigPaths: ["/opt/homebrew/etc/wireguard/SG.conf"]);

        result.Status.Should().Be(MacQuickStartStatus.Success);
        result.ShouldStartTunnel.Should().BeTrue();
    }

    [Fact]
    public void SelectConfig_UsesSavedConfigWhenItStillExists()
    {
        var result = MacQuickStartService.SelectConfig(
            "/opt/homebrew/etc/wireguard/SG.conf",
            [
                "/opt/homebrew/etc/wireguard/HK.conf",
                "/opt/homebrew/etc/wireguard/SG.conf"
            ]);

        result.Status.Should().Be(MacQuickStartStatus.Success);
        result.SelectedConfigPath.Should().Be("/opt/homebrew/etc/wireguard/SG.conf");
        result.Message.Should().Contain("SG.conf");
    }

    [Fact]
    public void SelectConfig_UsesOnlyDiscoveredConfigWhenSavedPathIsMissing()
    {
        var result = MacQuickStartService.SelectConfig(
            "/Users/user/Desktop/zip/US1.conf",
            ["/opt/homebrew/etc/wireguard/SG.conf"]);

        result.Status.Should().Be(MacQuickStartStatus.Success);
        result.SelectedConfigPath.Should().Be("/opt/homebrew/etc/wireguard/SG.conf");
    }

    [Fact]
    public void SelectConfig_AsksUserWhenMultipleConfigsExistAndSavedPathIsMissing()
    {
        var result = MacQuickStartService.SelectConfig(
            "/Users/user/Desktop/zip/US1.conf",
            [
                "/opt/homebrew/etc/wireguard/HK.conf",
                "/opt/homebrew/etc/wireguard/SG.conf"
            ]);

        result.Status.Should().Be(MacQuickStartStatus.MissingConfig);
        result.SelectedConfigPath.Should().BeNull();
        result.Message.Should().Contain("Choose a WireGuard config");
    }

    [Fact]
    public void SelectConfig_TellsUserWhereToPlaceConfigsWhenNoneAreFound()
    {
        var result = MacQuickStartService.SelectConfig(null, []);

        result.Status.Should().Be(MacQuickStartStatus.MissingConfig);
        result.SelectedConfigPath.Should().BeNull();
        result.Message.Should().Contain("/opt/homebrew/etc/wireguard");
    }
}
