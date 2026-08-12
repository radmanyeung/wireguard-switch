using FluentAssertions;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WindowsEnableTunnelCommandBuilderTests
{
    private const string ExePath = "C:\\Program Files\\WireGuard\\wireguard.exe";

    [Fact]
    public void ParseInstalledTunnelNames_FiltersStripsAndDedupes()
    {
        var names = WindowsTunnelServiceDiscovery.ParseInstalledTunnelNames(
        [
            "WireGuardTunnel$nordusa1",
            "WireGuardTunnel$SG",
            "wireguardtunnel$sg",
            "WireGuardTunnel$",
            "Schedule",
            "WpnService"
        ]);

        names.Should().Equal("nordusa1", "SG");
    }

    [Fact]
    public void BuildArguments_NoInstalledTunnels_InstallsSelectedOnly()
    {
        var args = WindowsEnableTunnelCommandBuilder.BuildArguments(
            ExePath,
            "C:\\configs\\SG.conf",
            []);

        args.Should().Be("\"C:\\Program Files\\WireGuard\\wireguard.exe\" /installtunnelservice \"C:\\configs\\SG.conf\"");
    }

    [Fact]
    public void BuildArguments_KillsEveryInstalledTunnelBeforeInstall()
    {
        var args = WindowsEnableTunnelCommandBuilder.BuildArguments(
            ExePath,
            "C:\\configs\\SG.conf",
            ["nordusa1", "TW"]);

        args.Should().Be(
            "\"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"nordusa1\""
            + " & \"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"TW\""
            + " & \"C:\\Program Files\\WireGuard\\wireguard.exe\" /installtunnelservice \"C:\\configs\\SG.conf\"");
    }

    [Fact]
    public void BuildArguments_SelectedTunnelAlsoInstalled_UninstallsItFirstForCleanReinstall()
    {
        var args = WindowsEnableTunnelCommandBuilder.BuildArguments(
            ExePath,
            "C:\\configs\\SG.conf",
            ["SG"]);

        args.Should().Contain("/uninstalltunnelservice \"SG\"");
        args.Should().EndWith("/installtunnelservice \"C:\\configs\\SG.conf\"");
    }

    [Fact]
    public void BuildArguments_DedupesAndIgnoresBlankNames()
    {
        var args = WindowsEnableTunnelCommandBuilder.BuildArguments(
            ExePath,
            "C:\\configs\\SG.conf",
            ["nordusa1", "NORDUSA1", "", "   "]);

        args.Should().Be(
            "\"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice \"nordusa1\""
            + " & \"C:\\Program Files\\WireGuard\\wireguard.exe\" /installtunnelservice \"C:\\configs\\SG.conf\"");
    }
}
